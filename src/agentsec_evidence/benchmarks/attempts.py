"""Serial execution and evidence-verified reuse for explicitly admitted treatments."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import portalocker
from pydantic import BaseModel, JsonValue, TypeAdapter

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import (
    AdmittedCellProgress,
    AdmittedEvidence,
    AdmittedFinish,
    AdmittedProgress,
    AdmittedState,
    AttemptEvidence,
    AttemptFinish,
    AttemptStart,
    AttemptStartV2,
    BenchmarkProgress,
    BenchmarkProgressV2,
    CellProgress,
    DependencyAttemptEvidence,
    DependencyAttemptFinish,
    DependencyBoundaryEvidence,
    DependencyBoundaryFinish,
    DependencyBoundaryProgress,
    DependencyBoundaryRow,
    DependencyCellProgress,
    DependencyMutationProgress,
    DependencyProgress,
    KicsAttemptEvidence,
    KicsAttemptFinish,
    KicsCellProgress,
    KicsProgress,
    PublicPilotEvidence,
    PublicPilotFinish,
    PublicPilotProgress,
    PublicPilotRow,
    ResearchEvidence,
    ResearchFinish,
    ResearchProgress,
    ResearchRow,
    RetryAuthorization,
    SemgrepAttemptFinish,
    SemgrepCellProgress,
    SemgrepProgress,
)
from agentsec_evidence.benchmarks.dependency_boundary_plan import CASE_ROOTS as BOUNDARY_CASE_ROOTS
from agentsec_evidence.benchmarks.dependency_evidence import verify_dependency_attempt
from agentsec_evidence.benchmarks.dependency_plan import CASE_ROOTS as DEPENDENCY_CASE_ROOTS
from agentsec_evidence.benchmarks.evidence import require_prelaunch_failure, verify_attempt_run
from agentsec_evidence.benchmarks.kics_evidence import verify_kics_attempt
from agentsec_evidence.benchmarks.kics_plan import CASE_ROOTS as KICS_CASE_ROOTS
from agentsec_evidence.benchmarks.models import (
    MAX_PLAN_BYTES,
    AdmittedCell,
    AdmittedPlan,
    AdmittedPreview,
    BenchmarkDryRunV3,
    BenchmarkPlan,
    BenchmarkPlanV2,
    DependencyBenchmarkPlan,
    DependencyBoundaryCell,
    DependencyBoundaryPlan,
    DependencyBoundaryPreview,
    DependencyCell,
    DependencyMutationCell,
    DependencyMutationPlan,
    DependencyMutationPreview,
    DependencyPreview,
    KicsBenchmarkPlan,
    KicsCell,
    KicsPreview,
    PlannedCell,
    PublicPilotBenchmarkPlan,
    PublicPilotCell,
    PublicPilotPreview,
    ResearchBenchmarkPlan,
    ResearchCell,
    ResearchPreview,
    SemgrepBenchmarkPlan,
    SemgrepCell,
    SemgrepPreview,
)
from agentsec_evidence.benchmarks.public_pilot_evidence import verify_public_pilot_attempt
from agentsec_evidence.benchmarks.research_evidence import verify_research_attempt
from agentsec_evidence.benchmarks.semgrep_evidence import verify_semgrep_attempt
from agentsec_evidence.benchmarks.semgrep_plan import CASE_ROOT
from agentsec_evidence.benchmarks.service import load_plan, validate_plan
from agentsec_evidence.core.identity import new_opaque_id, semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import model_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.dependencies.pipeline import run_dependency_scan
from agentsec_evidence.orchestration.agent_pipeline import AgentScanRequest, run_agent_scan
from agentsec_evidence.orchestration.kics_pipeline import KicsScanRequest, run_kics_scan
from agentsec_evidence.orchestration.pipeline import SemgrepScanRequest, run_semgrep_scan
from agentsec_evidence.orchestration.shared import resolve_docker
from agentsec_evidence.pilot.runner import run_source_pilot
from agentsec_evidence.research.controlled import run_controlled_research_case
from agentsec_evidence.research.retained import bounded_file, plain_path

MAX_RECORD_BYTES = 2 * 1024**2
REUSABLE = {
    "partial-analysis",
    "refused",
    "completed-with-findings",
    "completed-without-findings",
    "unsupported",
}


def _row_model(
    dry: AdmittedPreview,
) -> (
    type[CellProgress]
    | type[SemgrepCellProgress]
    | type[KicsCellProgress]
    | type[DependencyCellProgress]
    | type[DependencyBoundaryRow]
    | type[PublicPilotRow]
    | type[ResearchRow]
):
    if isinstance(dry, ResearchPreview):
        return ResearchRow
    if isinstance(dry, PublicPilotPreview):
        return PublicPilotRow
    if isinstance(dry, DependencyBoundaryPreview):
        return DependencyBoundaryRow
    if isinstance(dry, DependencyPreview | DependencyMutationPreview):
        return DependencyCellProgress
    if isinstance(dry, KicsPreview):
        return KicsCellProgress
    return SemgrepCellProgress if isinstance(dry, SemgrepPreview) else CellProgress


def _finish_model(
    plan: AdmittedPlan,
) -> (
    type[AttemptFinish]
    | type[SemgrepAttemptFinish]
    | type[KicsAttemptFinish]
    | type[DependencyAttemptFinish]
    | type[DependencyBoundaryFinish]
    | type[PublicPilotFinish]
    | type[ResearchFinish]
):
    if isinstance(plan, ResearchBenchmarkPlan):
        return ResearchFinish
    if isinstance(plan, PublicPilotBenchmarkPlan):
        return PublicPilotFinish
    if isinstance(plan, DependencyBoundaryPlan):
        return DependencyBoundaryFinish
    if isinstance(plan, DependencyBenchmarkPlan | DependencyMutationPlan):
        return DependencyAttemptFinish
    if isinstance(plan, KicsBenchmarkPlan):
        return KicsAttemptFinish
    return SemgrepAttemptFinish if isinstance(plan, SemgrepBenchmarkPlan) else AttemptFinish


@dataclass
class History:
    rows: list[AdmittedCellProgress] = field(default_factory=list)
    attempts: list[AdmittedCellProgress] = field(default_factory=list)
    previous: str | None = None


def _write_once(path: Path, raw: bytes) -> None:
    plain_path(path.parent, directory=True)
    # A torn write is deliberately left as invalid evidence, never silently overwritten.
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _read[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    return model.model_validate(
        load_agent_json(bounded_file(path, MAX_RECORD_BYTES), max_bytes=MAX_RECORD_BYTES)
    )


def _mkdir(path: Path) -> Path:
    plain_path(path.parent, directory=True)
    path.mkdir(exist_ok=True)
    return plain_path(path, directory=True)


def _session_path(project: Path, dry: AdmittedPreview) -> Path:
    return project / "workspace/benchmarks" / dry.plan_semantic_sha256


@contextmanager
def _writer(root: Path) -> Iterator[None]:
    lock = root / ".writer.lock"
    if os.path.lexists(lock):
        plain_path(lock, directory=False)
    try:
        # Never unlink a shared lock inode: another process may already be waiting on it.
        with portalocker.Lock(str(lock), mode="a+", timeout=0):
            plain_path(lock, directory=False)
            yield
    except portalocker.exceptions.LockException as exc:
        raise ValueError("Benchmark writer is active; no duplicate launch permitted") from exc


def _names(root: Path, *, allowed: set[str]) -> set[str]:
    plain_path(root, directory=True)
    names: set[str] = set()
    for path in root.iterdir():
        if path.name not in allowed:
            raise ValueError("Unexpected benchmark history entry")
        names.add(path.name)
    return names


def _history(project: Path, session: Path, dry: AdmittedPreview) -> History:
    if _names(session, allowed={"plan.json", "validation.json", "attempts"}) != {
        "plan.json",
        "validation.json",
        "attempts",
    }:
        raise ValueError("Incomplete benchmark initialization; retain for explicit recovery")
    if sha256_bytes(bounded_file(session / "plan.json", MAX_PLAN_BYTES)) != dry.plan_sha256:
        raise ValueError("Frozen plan bytes changed")
    if _read(session / "validation.json", type(dry)) != dry:
        raise ValueError("Frozen validation receipt differs")
    plan = load_plan(session / "plan.json")
    retry_enabled = isinstance(dry, BenchmarkDryRunV3)
    attempts = plain_path(session / "attempts", directory=True)
    paths: list[Path] = []
    for path in attempts.iterdir():
        if len(paths) >= len(dry.cells) * (2 if retry_enabled else 1):
            raise ValueError("Excess or duplicate benchmark attempts")
        paths.append(plain_path(path, directory=True))
    paths.sort()
    history = History()
    blocked = False
    seen_runs: set[str] = set()
    seen_attempts: set[str] = set()
    previous_finish: AdmittedFinish | None = None
    for index, path in enumerate(paths):
        names = _names(path, allowed={"start.json", "finish.json", "execution"})
        if not {"start.json", "execution"}.issubset(names):
            raise ValueError("Incomplete attempt initialization; retain for explicit recovery")
        start: AttemptStart | AttemptStartV2 = (
            _read(path / "start.json", AttemptStartV2)
            if retry_enabled
            else _read(path / "start.json", AttemptStart)
        )
        if start.attempt_id in seen_attempts:
            raise ValueError("Duplicate attempt identity")
        seen_attempts.add(start.attempt_id)
        retry = start.retry if isinstance(start, AttemptStartV2) else None
        if retry is not None:
            if (
                not blocked
                or not history.rows
                or previous_finish is None
                or previous_finish.evidence is None
                or previous_finish.state != "execution-failed"
                or retry.prior_attempt_id != history.attempts[-1].attempt_id
                or sum(row.cell_id == start.cell_id for row in history.attempts) != 1
            ):
                raise ValueError("Retry does not follow one eligible failed attempt")
            if not isinstance(previous_finish.evidence, AttemptEvidence):
                raise ValueError("Retry is limited to the admitted agent treatment")
            require_prelaunch_failure(paths[index - 1] / "execution", previous_finish.evidence)
            cell_index = len(history.rows) - 1
        else:
            if blocked:
                raise ValueError("History continues beyond a failed or interrupted attempt")
            cell_index = len(history.rows)
        if cell_index >= len(dry.cells):
            raise ValueError("Excess or duplicate benchmark attempts")
        cell = dry.cells[cell_index]
        if (
            path.name != f"{index + 1:04d}_{start.attempt_id}"
            or start.ordinal != index + 1
            or start.cell_id != cell.cell_id
            or start.case_id != cell.case_id
            or start.repetition != cell.repetition
            or start.plan_sha256 != dry.plan_sha256
            or start.previous_finish_sha256 != history.previous
        ):
            raise ValueError("Attempt ordering, identity or history chain differs")
        execution = plain_path(path / "execution", directory=True)
        state = "interrupted"
        evidence = None
        if "finish.json" in names:
            finish: AdmittedFinish = _read(path / "finish.json", _finish_model(plan))
            if bounded_file(path / "finish.json", MAX_RECORD_BYTES) != model_bytes(finish):
                raise ValueError("Attempt completion bytes are not canonical")
            if finish.attempt_id != start.attempt_id or finish.start_sha256 != sha256_bytes(
                bounded_file(path / "start.json", MAX_RECORD_BYTES)
            ):
                raise ValueError("Attempt completion does not bind its start")
            if finish.evidence is not None:
                evidence = _verify(project, execution, finish.evidence.run_id, plan, cell)
                if evidence != finish.evidence:
                    raise ValueError("Retained attempt evidence changed")
                if evidence.run_id in seen_runs:
                    raise ValueError("Repeated cells cannot reuse the same run identity")
                seen_runs.add(evidence.run_id)
            state = finish.state
            history.previous = sha256_bytes(bounded_file(path / "finish.json", MAX_RECORD_BYTES))
            previous_finish = finish
        else:
            history.previous = None
            previous_finish = None
        blocked = state not in REUSABLE
        row_model = _row_model(dry)
        counters: dict[str, object] = {}
        if isinstance(dry, ResearchPreview):
            counters = {
                "rows": [r.model_dump(mode="json") for r in evidence.rows]
                if isinstance(evidence, ResearchEvidence)
                else None,
                "syntax_invocations": evidence.syntax_invocations
                if isinstance(evidence, ResearchEvidence)
                else None,
                "case_state": evidence.case_state
                if isinstance(evidence, ResearchEvidence)
                else None,
            }
        if isinstance(dry, PublicPilotPreview):
            counters = {
                "rows": [r.model_dump(mode="json") for r in evidence.rows]
                if isinstance(evidence, PublicPilotEvidence)
                else None,
                "syntax_invocations": evidence.syntax_invocations
                if isinstance(evidence, PublicPilotEvidence)
                else None,
            }
        if isinstance(dry, DependencyBoundaryPreview):
            counters = {
                "stages": [s.model_dump(mode="json") for s in evidence.stages]
                if isinstance(evidence, DependencyBoundaryEvidence)
                else None,
                "eligible_packages": evidence.eligible_packages
                if isinstance(evidence, DependencyBoundaryEvidence)
                else None,
                "separate_local_packages": evidence.separate_local_packages
                if isinstance(evidence, DependencyBoundaryEvidence)
                else None,
                "input_failure": evidence.input_failure
                if isinstance(evidence, DependencyBoundaryEvidence)
                else None,
            }
        if isinstance(dry, DependencyPreview | DependencyMutationPreview):
            counters = {
                "stages": [s.model_dump(mode="json") for s in evidence.stages]
                if isinstance(evidence, DependencyAttemptEvidence)
                else None,
                "eligible_packages": evidence.eligible_packages
                if isinstance(evidence, DependencyAttemptEvidence)
                else None,
                "separate_local_packages": evidence.separate_local_packages
                if isinstance(evidence, DependencyAttemptEvidence)
                else None,
            }
        if isinstance(dry, KicsPreview):
            counters = {
                "native_files_scanned": evidence.native_files_scanned
                if isinstance(evidence, KicsAttemptEvidence)
                else None,
                "native_files_parsed": evidence.native_files_parsed
                if isinstance(evidence, KicsAttemptEvidence)
                else None,
                "native_queries_total": evidence.native_queries_total
                if isinstance(evidence, KicsAttemptEvidence)
                else None,
            }
        row = row_model.model_validate(
            {
                **counters,
                "cell_id": cell.cell_id,
                "case_id": cell.case_id,
                "repetition": cell.repetition,
                "state": state,
                "attempt_id": start.attempt_id,
                "run_id": evidence.run_id if evidence else None,
                "finding_records": evidence.finding_records if evidence else None,
                "scanner_invocations": evidence.scanner_invocations if evidence else None,
                "verified_terminal_attempt": evidence is not None,
            }
        )
        history.attempts.append(row)
        if retry is not None:
            history.rows[-1] = row
        else:
            history.rows.append(row)
    return history


def _progress(
    session: Path,
    dry: AdmittedPreview,
    history: History,
    *,
    new: int = 0,
    reused: int = 0,
    retried: bool = False,
) -> AdmittedProgress:
    rows = history.rows
    row_model = _row_model(dry)
    all_rows = rows + [
        row_model.model_validate(
            {
                "cell_id": cell.cell_id,
                "case_id": cell.case_id,
                "repetition": cell.repetition,
                "state": "not-attempted",
            }
        )
        for cell in dry.cells[len(rows) :]
    ]
    blocked = any(row.state not in REUSABLE for row in rows)
    fields = dict(
        plan_sha256=dry.plan_sha256,
        plan_semantic_sha256=dry.plan_semantic_sha256,
        session=str(session),
        cells=[r.model_dump(mode="json") for r in all_rows],
        workflow_complete=len(rows) == len(dry.cells) and not blocked,
        blocked=blocked,
        newly_attempted_cells=0 if retried else new,
        reused_verified_cells=reused,
    )
    if isinstance(dry, SemgrepPreview):
        return SemgrepProgress.model_validate(fields)
    if isinstance(dry, PublicPilotPreview):
        return PublicPilotProgress.model_validate(fields)
    if isinstance(dry, ResearchPreview):
        return ResearchProgress.model_validate(fields)
    if isinstance(dry, KicsPreview):
        return KicsProgress.model_validate(fields)
    if isinstance(dry, DependencyPreview):
        return DependencyProgress.model_validate(fields)
    if isinstance(dry, DependencyMutationPreview):
        return DependencyMutationProgress.model_validate(fields)
    if isinstance(dry, DependencyBoundaryPreview):
        return DependencyBoundaryProgress.model_validate(fields)
    progress = BenchmarkProgress.model_validate(fields)
    if isinstance(dry, BenchmarkDryRunV3):
        return BenchmarkProgressV2.model_validate(
            {
                **progress.model_dump(mode="json", exclude={"contract", "limitations"}),
                "attempts": [row.model_dump(mode="json") for row in history.attempts],
                "newly_created_attempts": new,
                "manual_retry_attempts": len(history.attempts) - len(rows),
            }
        )
    return progress


def inspect_benchmark(project: Path, plan_path: Path) -> AdmittedProgress:
    """Replay local retained attempts without executing a producer or repairing history."""
    project = plain_path(project, directory=True)
    dry = validate_plan(project, plan_path)
    session = _session_path(project, dry)
    if not os.path.lexists(session):
        return _progress(session, dry, History())
    plain_path(session.parent, directory=True)
    with _writer(session.parent):
        history = _history(project, session, dry)
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed during history verification")
        return _progress(session, dry, history)


def replay_retained_history(
    project: Path, session: Path, *, plan_sha256: str, validation_sha256: str
) -> tuple[AdmittedPlan, AdmittedPreview, History]:
    """Read pinned historical evidence, not current-code execution/resume authorization."""
    project = plain_path(project, directory=True)
    session = plain_path(session, directory=True)
    if session.parent != project / "workspace/benchmarks":
        raise ValueError("Historical replay requires an existing governed session")
    # Exclusive locking also works without optional Windows shared-lock dependencies.
    # Open the existing lock read-only: historical replay must not create or modify it.
    lock = plain_path(session.parent / ".writer.lock", directory=False)
    with portalocker.Lock(
        str(lock), mode="rb", timeout=0, flags=portalocker.LOCK_EX | portalocker.LOCK_NB
    ):
        raw_plan = bounded_file(session / "plan.json", MAX_PLAN_BYTES)
        raw_validation = bounded_file(session / "validation.json", MAX_RECORD_BYTES)
        if (
            sha256_bytes(raw_plan) != plan_sha256
            or sha256_bytes(raw_validation) != validation_sha256
        ):
            raise ValueError("Historical plan/validation pin changed")
        plan = load_plan(session / "plan.json")
        dry: AdmittedPreview = TypeAdapter(AdmittedPreview).validate_python(
            load_agent_json(raw_validation, max_bytes=MAX_RECORD_BYTES)
        )
        expected_contract = (
            "benchmark-dry-run-v3"
            if isinstance(plan, BenchmarkPlanV2)
            else "benchmark-dry-run-v2"
            if isinstance(plan, BenchmarkPlan)
            else plan.contract.replace("-plan-", "-dry-run-")
        )
        if (
            dry.contract != expected_contract
            or dry.plan_sha256 != plan_sha256
            or dry.plan_semantic_sha256 != semantic_hash(plan.model_dump(mode="json"))
            or session.name != dry.plan_semantic_sha256
            or dry.plan_id != plan.plan_id
            or dry.implementation_sha256
            != semantic_hash([pin.model_dump(mode="json") for pin in plan.implementation])
        ):
            raise ValueError("Historical validation does not bind the frozen plan")
        cases = (plan,) if isinstance(plan, PublicPilotBenchmarkPlan) else plan.cases
        expected_cells = [
            (case, repeat) for case in cases for repeat in range(1, plan.repetitions + 1)
        ]
        if len(dry.cells) != len(expected_cells):
            raise ValueError("Historical preview omits frozen cells")
        retained_cells: tuple[AdmittedCell, ...] = dry.cells
        for cell, (case, repeat) in zip(retained_cells, expected_cells, strict=True):
            identity: dict[str, JsonValue] = {
                "plan": dry.plan_semantic_sha256,
                "case": case.case_id,
            }
            if not isinstance(plan, ResearchBenchmarkPlan | PublicPilotBenchmarkPlan):
                identity["repetition"] = repeat
            if (cell.case_id, cell.repetition, cell.cell_id) != (
                case.case_id,
                repeat,
                semantic_hash(identity),
            ):
                raise ValueError("Historical cell differs from frozen plan ordering")
            for original, expanded in (
                ("files", "input_files"),
                ("selected_paths", "selected_paths"),
                ("expectation", "expectation"),
                ("expectation_sha256", "expectation_sha256"),
                ("mutation", "mutation"),
            ):
                if (
                    hasattr(case, original)
                    and hasattr(cell, expanded)
                    and getattr(case, original) != getattr(cell, expanded)
                ):
                    raise ValueError("Historical cell evidence binding differs from plan")
        history = _history(project, session, dry)
        if (
            bounded_file(session / "plan.json", MAX_PLAN_BYTES) != raw_plan
            or bounded_file(session / "validation.json", MAX_RECORD_BYTES) != raw_validation
        ):
            raise ValueError("Historical input changed during replay")
        return plan, dry, history


def run_benchmark(project: Path, plan_path: Path, *, max_new_cells: int = 39) -> AdmittedProgress:
    """Run only not-attempted cells; never retry, repair, or erase failed attempts."""
    if type(max_new_cells) is not int or not 1 <= max_new_cells <= 39:
        raise ValueError("max_new_cells must be an integer between 1 and 39")
    project = plain_path(project, directory=True)
    dry = validate_plan(project, plan_path)
    root = _mkdir(_mkdir(project / "workspace") / "benchmarks")
    session = _session_path(project, dry)
    with _writer(root):
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed before benchmark execution")
        if not os.path.lexists(session):
            session.mkdir(exist_ok=False)
            raw = bounded_file(plan_path, MAX_PLAN_BYTES)
            if sha256_bytes(raw) != dry.plan_sha256:
                raise ValueError("Plan changed during initialization")
            _write_once(session / "plan.json", raw)
            _write_once(session / "validation.json", model_bytes(dry))
            (session / "attempts").mkdir()
        history = _history(project, session, dry)
        initial = _progress(session, dry, history)
        if initial.blocked:
            return initial
        reused = len(history.rows)
        new = 0
        for index in range(reused, min(len(dry.cells), reused + max_new_cells)):
            if validate_plan(project, plan_path) != dry:
                raise ValueError("Plan changed before cell dispatch")
            state = _dispatch(project, plan_path, session, dry, history, dry.cells[index])
            new += 1
            history = _history(project, session, dry)
            if state not in REUSABLE:
                break
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed during benchmark execution; history retained")
        return _progress(session, dry, history, new=new, reused=reused)


def _verify(
    project: Path, execution: Path, run_id: str, plan: AdmittedPlan, cell: AdmittedCell
) -> AdmittedEvidence:
    if isinstance(plan, ResearchBenchmarkPlan) and isinstance(cell, ResearchCell):
        return verify_research_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, PublicPilotBenchmarkPlan) and isinstance(cell, PublicPilotCell):
        return verify_public_pilot_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, SemgrepBenchmarkPlan) and isinstance(cell, SemgrepCell):
        return verify_semgrep_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, KicsBenchmarkPlan) and isinstance(cell, KicsCell):
        return verify_kics_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, DependencyBenchmarkPlan) and isinstance(cell, DependencyCell):
        return verify_dependency_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, DependencyMutationPlan) and isinstance(cell, DependencyMutationCell):
        return verify_dependency_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, DependencyBoundaryPlan) and isinstance(cell, DependencyBoundaryCell):
        return verify_dependency_attempt(project, execution, run_id, plan, cell)
    if isinstance(plan, BenchmarkPlan | BenchmarkPlanV2) and isinstance(cell, PlannedCell):
        return verify_attempt_run(project, execution, run_id, plan, cell)
    raise ValueError("Benchmark producer and cell contracts differ")


def _dispatch(
    project: Path,
    plan_path: Path,
    session: Path,
    dry: AdmittedPreview,
    history: History,
    cell: AdmittedCell,
    retry: RetryAuthorization | None = None,
) -> AdmittedState:
    """The first attempt and an authorized retry share exactly the same producer path."""
    plan = load_plan(session / "plan.json")
    attempt_id = new_opaque_id("attempt")
    ordinal = len(history.attempts) + 1
    path = session / "attempts" / f"{ordinal:04d}_{attempt_id}"
    path.mkdir(exist_ok=False)
    execution = path / "execution"
    execution.mkdir()
    fields = {
        "attempt_id": attempt_id,
        "ordinal": ordinal,
        "cell_id": cell.cell_id,
        "case_id": cell.case_id,
        "repetition": cell.repetition,
        "plan_sha256": dry.plan_sha256,
        "previous_finish_sha256": history.previous,
        "started_at": utc_now(),
    }
    start = (
        AttemptStartV2.model_validate({**fields, "retry": retry})
        if isinstance(dry, BenchmarkDryRunV3)
        else AttemptStart.model_validate(fields)
    )
    raw_start = model_bytes(start)
    _write_once(path / "start.json", raw_start)
    began = time.monotonic_ns()
    evidence = None
    error_kind = None
    interrupted = False
    state: AdmittedState
    try:
        if isinstance(plan, ResearchBenchmarkPlan):
            (execution / "environment").mkdir()
            for pin in plan.pins:
                if pin.path in {"pyproject.toml", "uv.lock"}:
                    raw = bounded_file(project / pin.path, MAX_RECORD_BYTES)
                    if len(raw) != pin.bytes or sha256_bytes(raw) != pin.sha256:
                        raise ValueError("Controlled environment changed before dispatch")
                    _write_once(execution / "environment" / pin.path, raw)
            run_controlled_research_case(
                project=project,
                rule_source=project / plan.rule_source,
                output=execution / "case",
                case_id=cell.case_id,
            )
            run_id = (
                "research-"
                + semantic_hash(
                    {
                        "manifest": sha256_file(execution / "case/evidence-manifest.json"),
                        "case": cell.case_id,
                    }
                )[:32]
            )
        elif isinstance(plan, PublicPilotBenchmarkPlan):
            run_source_pilot(
                project=project,
                cache=project / plan.cache_path,
                rule_source=project / plan.rule_source,
                database=project / plan.database.path,
                output=execution / "pilot",
            )
            run_id = (
                "public-pilot-"
                + semantic_hash(
                    {"manifest": sha256_file(execution / "pilot/evidence-manifest.json")}
                )[:32]
            )
        elif isinstance(plan, SemgrepBenchmarkPlan):
            result = run_semgrep_scan(
                SemgrepScanRequest(
                    project_root=project,
                    workspace_root=execution,
                    target_source=project / CASE_ROOT / "target",
                    source_label="fixture:semgrep-basic",
                    revision="fixture-v1",
                    run_label="benchmark:dev-semgrep-basic-v1",
                    source_kind="project-fixture",
                    license_status="project-authored-private",
                )
            )
            run_id = result.run_id
        elif isinstance(plan, KicsBenchmarkPlan) and isinstance(cell, KicsCell):
            relative = KICS_CASE_ROOTS[cell.case_id]
            result = run_kics_scan(
                KicsScanRequest(
                    project_root=project,
                    workspace_root=execution,
                    target_source=project / relative / "target",
                    source_label="fixture:" + relative.rsplit("/", 1)[-1],
                    revision="fixture-v1",
                    run_label="benchmark:" + cell.case_id,
                    source_kind="project-fixture",
                    license_status="project-authored-private",
                )
            )
            run_id = result.run_id
        elif isinstance(
            plan, DependencyBenchmarkPlan | DependencyMutationPlan | DependencyBoundaryPlan
        ) and isinstance(cell, DependencyCell | DependencyMutationCell | DependencyBoundaryCell):
            if isinstance(cell, DependencyBoundaryCell):
                relative = BOUNDARY_CASE_ROOTS[cell.case_id]
            else:
                source_case = (
                    "dev-dependency-basic-v1"
                    if isinstance(cell, DependencyMutationCell)
                    else cell.case_id
                )
                relative = DEPENDENCY_CASE_ROOTS[source_case]
            paired = run_dependency_scan(
                project_root=project,
                workspace_root=execution,
                source=project / relative / "target",
                label="fixture:" + relative.rsplit("/", 1)[-1],
                revision="fixture-v1",
                database=project / plan.database.path,
                database_sha256=plan.database.sha256,
                mutation=cell.mutation if isinstance(cell, DependencyMutationCell) else None,
            )
            if not isinstance(paired.get("run_id"), str):
                raise ValueError("Dependency producer returned no run identity")
            run_id = str(paired["run_id"])
        else:
            result = run_agent_scan(AgentScanRequest(project, execution, cell.case_id))
            run_id = result.run_id
        evidence = _verify(project, execution, run_id, plan, cell)
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed during cell execution")
        state = evidence.state
    except KeyboardInterrupt:
        state, error_kind, interrupted = "interrupted", "keyboard-interrupt", True
        evidence = None
    except Exception:
        # Do not put potentially sensitive exception text into portable history.
        state, error_kind, evidence = "execution-failed", "runner-or-verification-error", None
    finish_model = _finish_model(plan)
    finish = finish_model.model_validate(
        {
            "attempt_id": attempt_id,
            "start_sha256": sha256_bytes(raw_start),
            "ended_at": utc_now(),
            "duration_ns": time.monotonic_ns() - began,
            "state": state,
            "error_kind": error_kind,
            "evidence": evidence.model_dump(mode="json") if evidence else None,
        }
    )
    _write_once(path / "finish.json", model_bytes(finish))
    if interrupted:
        raise KeyboardInterrupt
    return state


def retry_benchmark(
    project: Path,
    plan_path: Path,
    *,
    attempt_id: str,
    cause: str,
    remediation: str,
) -> BenchmarkProgressV2:
    """Retry one verified pre-launch failure only; never continue subsequent cells implicitly."""
    authorization = RetryAuthorization.model_validate(
        {"prior_attempt_id": attempt_id, "cause": cause, "remediation": remediation}
    )
    project = plain_path(project, directory=True)
    dry = validate_plan(project, plan_path)
    if not isinstance(dry, BenchmarkDryRunV3):
        raise ValueError("Frozen plan does not authorize a manual retry")
    session = plain_path(_session_path(project, dry), directory=True)
    with _writer(session.parent):
        history = _history(project, session, dry)
        if not history.attempts or history.attempts[-1].attempt_id != attempt_id:
            raise ValueError("Retry must explicitly select the latest failed attempt")
        latest = history.attempts[-1]
        if (
            latest.state != "execution-failed"
            or not latest.verified_terminal_attempt
            or sum(row.cell_id == latest.cell_id for row in history.attempts) != 1
        ):
            raise ValueError("Attempt is not eligible or its one manual retry is exhausted")
        prior = session / "attempts" / f"{len(history.attempts):04d}_{attempt_id}"
        finish = _read(prior / "finish.json", AttemptFinish)
        if finish.evidence is None:
            raise ValueError("Retry requires verified retained failure evidence")
        require_prelaunch_failure(prior / "execution", finish.evidence)
        if resolve_docker(None) is None:
            raise ValueError("Docker command is still unavailable; no retry attempt created")
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed before retry dispatch")
        _dispatch(
            project,
            plan_path,
            session,
            dry,
            history,
            dry.cells[len(history.rows) - 1],
            authorization,
        )
        history = _history(project, session, dry)
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed during retry; both attempts retained")
        result = _progress(session, dry, history, new=1, retried=True)
        assert isinstance(result, BenchmarkProgressV2)
        return result
