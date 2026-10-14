"""Serial execution and conservative resume for the existing authored agent treatment."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import portalocker
from pydantic import BaseModel

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
    RetryAuthorization,
    SemgrepAttemptFinish,
    SemgrepCellProgress,
    SemgrepProgress,
)
from agentsec_evidence.benchmarks.evidence import require_prelaunch_failure, verify_attempt_run
from agentsec_evidence.benchmarks.models import (
    MAX_PLAN_BYTES,
    AdmittedCell,
    AdmittedPlan,
    AdmittedPreview,
    BenchmarkDryRunV3,
    PlannedCell,
    SemgrepBenchmarkPlan,
    SemgrepCell,
    SemgrepPreview,
)
from agentsec_evidence.benchmarks.semgrep_evidence import verify_semgrep_attempt
from agentsec_evidence.benchmarks.semgrep_plan import CASE_ROOT
from agentsec_evidence.benchmarks.service import load_plan, validate_plan
from agentsec_evidence.core.identity import new_opaque_id, sha256_bytes
from agentsec_evidence.core.io import model_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.orchestration.agent_pipeline import AgentScanRequest, run_agent_scan
from agentsec_evidence.orchestration.pipeline import SemgrepScanRequest, run_semgrep_scan
from agentsec_evidence.orchestration.shared import resolve_docker
from agentsec_evidence.research.retained import bounded_file, plain_path

MAX_RECORD_BYTES = 2 * 1024**2
REUSABLE = {"partial-analysis", "refused", "completed-with-findings", "completed-without-findings"}


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
            finish: AdmittedFinish = (
                _read(path / "finish.json", SemgrepAttemptFinish)
                if isinstance(dry, SemgrepPreview)
                else _read(path / "finish.json", AttemptFinish)
            )
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
        row_model = SemgrepCellProgress if isinstance(dry, SemgrepPreview) else CellProgress
        row = row_model.model_validate(
            {
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
    row_model = SemgrepCellProgress if isinstance(dry, SemgrepPreview) else CellProgress
    all_rows = rows + [
        row_model(
            cell_id=cell.cell_id,
            case_id=cell.case_id,
            repetition=cell.repetition,
            state="not-attempted",
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
    if isinstance(plan, SemgrepBenchmarkPlan) and isinstance(cell, SemgrepCell):
        return verify_semgrep_attempt(project, execution, run_id, plan, cell)
    if not isinstance(plan, SemgrepBenchmarkPlan) and isinstance(cell, PlannedCell):
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
        if isinstance(plan, SemgrepBenchmarkPlan):
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
        else:
            result = run_agent_scan(AgentScanRequest(project, execution, cell.case_id))
        evidence = _verify(project, execution, result.run_id, plan, cell)
        if validate_plan(project, plan_path) != dry:
            raise ValueError("Plan changed during cell execution")
        state = evidence.state
    except KeyboardInterrupt:
        state, error_kind, interrupted = "interrupted", "keyboard-interrupt", True
        evidence = None
    except Exception:
        # Do not put potentially sensitive exception text into portable history.
        state, error_kind, evidence = "execution-failed", "runner-or-verification-error", None
    finish_model = SemgrepAttemptFinish if isinstance(plan, SemgrepBenchmarkPlan) else AttemptFinish
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
