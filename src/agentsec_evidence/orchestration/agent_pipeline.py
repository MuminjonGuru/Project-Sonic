from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.adapters.agent_audit import normalize_agent_audit, parse_agent_audit_json
from agentsec_evidence.agents.development import load_development_case, materialize_case
from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.inputs import plan_agent_input_admission
from agentsec_evidence.agents.models import AgentArtifact, AgentAssessment, AnalysisState
from agentsec_evidence.agents.records import (
    AgentInputCheck,
    AgentInputReport,
    AgentInputRequest,
    AgentParserReport,
    AgentRunDetails,
    verify_input_report,
)
from agentsec_evidence.agents.semantics import agent_semantic_document, native_projection
from agentsec_evidence.agents.url_contrast import CASE_IDS as URL_CONTRAST_CASE_IDS
from agentsec_evidence.agents.url_contrast import CASE_SET as URL_CONTRAST_CASE_SET
from agentsec_evidence.agents.url_contrast import load_url_contrast_case
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import new_opaque_id, semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes, json_bytes, model_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.docker import portable_docker_argv
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.models.contracts import (
    BlobDescriptor,
    BlobIndex,
    CoverageRecord,
    ExecutionOutcome,
    FailureCategory,
    FailureRecord,
    Finding,
    RunState,
    Sensitivity,
)
from agentsec_evidence.orchestration.shared import (
    PipelineResult,
    cleanup_container,
    failure_record,
    finish_run,
    make_execution,
    prepare_workspace,
    resolve_docker,
    store_blob,
)
from agentsec_evidence.storage.bundle import RunBundle


@dataclass(frozen=True)
class AgentScanRequest:
    project_root: Path
    workspace_root: Path
    case_id: str
    docker_executable: Path | None = None


def run_agent_scan(request: AgentScanRequest) -> PipelineResult:
    started = time.monotonic_ns()
    project = request.project_root.resolve(strict=True)
    workspace = request.workspace_root.resolve()
    if request.case_id in URL_CONTRAST_CASE_IDS:
        case, cases_raw = load_url_contrast_case(project, request.case_id)
        case_set = URL_CONTRAST_CASE_SET
    else:
        case, cases_raw = load_development_case(project, request.case_id)
        case_set = "agent-artifact-development-v1"
    profile = load_toml_config(
        project / "configs/profiles/agent-development.toml", ExecutionProfile
    )
    tool = load_toml_config(project / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    if profile.value.profile_kind != "development" or profile.value.max_workers != 1:
        raise ValueError("This runner admits sequential development execution only")
    staging = workspace / "agent-inputs" / new_opaque_id("view")
    materialize_case(case, staging / "target")
    prepared = prepare_workspace(
        workspace_root=workspace,
        target_source=staging / "target",
        source_label=f"agent-development:{case.id}",
        revision=case_set,
        source_kind="project-fixture",
        license_status="project-authored-private",
    )
    snapshot = prepared.snapshot_result
    worker_request = AgentInputRequest(
        target_snapshot_id=snapshot.snapshot.snapshot_id,
        inventory=list(snapshot.inventory),
        selected={case.input_path: case.artifact_kind},
    )
    request_raw = model_bytes(worker_request)
    request_path = staging / "request.json"
    atomic_write_bytes(request_path, request_raw)
    # Freeze the trusted worker code, not a target environment. Never import target modules.
    source_records: list[JsonValue] = []
    for source in sorted((project / "src").rglob("*.py")):
        relative = source.relative_to(project / "src").as_posix()
        raw = source.read_bytes()
        atomic_write_bytes(staging / "worker-source" / relative, raw)
        source_records.append({"path": relative, "sha256": sha256_bytes(raw)})
    rules = json_bytes(
        {"image": tool.value.image, "selection": "builtin-rules/severity-info/static-only"}
    )
    config_sha = semantic_hash(
        {
            "profile": profile.sha256,
            "tool": tool.sha256,
            "rules": sha256_bytes(rules),
            "worker_sources": source_records,
            "case_registry": sha256_bytes(cases_raw),
        }
    )
    docker = resolve_docker(request.docker_executable)
    with RunBundle.create(
        workspace,
        run_label=f"agent-development:{case.id}",
        profile_id=profile.value.profile_id,
        config_sha256=config_sha,
        snapshot_result=snapshot,
    ) as bundle:
        bundle.run.semantic_hash_version = "agent-run-semantic-v1"
        execution_id = new_opaque_id("execution")
        bundle.add_execution_id(execution_id)
        prefix = f"executions/{execution_id}"
        descriptors: list[BlobDescriptor] = []

        def retain(
            name: str, data: bytes, role: str, media: str = "application/json"
        ) -> BlobDescriptor:
            descriptor = store_blob(
                bundle=bundle,
                blob_store=prepared.blob_store,
                relative_path=f"{prefix}/{name}",
                data=data,
                media_type=media,
                sensitivity=Sensitivity.INTERNAL,
                producer="agent-development-runner",
                logical_role=role,
            )
            descriptors.append(descriptor)
            return descriptor

        retain("inputs/profile.toml", profile.raw, "execution-profile", "application/toml")
        retain("inputs/tool-config.toml", tool.raw, "tool-config", "application/toml")
        retain("inputs/rules.json", rules, "ruleset")
        retain("inputs/worker-sources.json", json_bytes(source_records), "worker-code-identity")
        retain("inputs/cases.json", cases_raw, "development-case-registry")
        retain("inputs/request.json", request_raw, "agent-input-request")
        for entry in snapshot.inventory:
            raw = (snapshot.content_root / entry.path).read_bytes()
            if len(raw) != entry.byte_length or sha256_bytes(raw) != entry.sha256:
                raise ValueError("Snapshot changed before execution")
            retain(f"inputs/target/{entry.path}", raw, "target-input", entry.media_type)
        bundle.transition(
            RunState.PLANNED, "registered authored case and restricted treatment recorded"
        )
        failures: list[FailureRecord] = []
        report: AgentInputReport | None = None
        checks: list[AgentInputCheck] = [
            AgentInputCheck(
                artifact=AgentArtifact(
                    target_snapshot_id=snapshot.snapshot.snapshot_id,
                    source=next(
                        item for item in snapshot.inventory if item.path == case.input_path
                    ),
                    kind=case.artifact_kind,
                    format_id=None,
                    parse_state="not-run",
                    reason="Bounded input validation has not completed",
                ),
                line_count=None,
                suppression_lines=[],
            )
        ]
        blockers = ["validation-not-complete"]
        worker_capture: ProcessCapture | None = None
        scanner_capture: ProcessCapture | None = None
        scanner_argv = ["docker", "run"]
        scanner_cleanup: bool | None = None
        scanner_launched = False
        native_raw: bytes | None = None
        native_semantics: JsonValue = None
        native_sha: str | None = None
        parser_report: AgentParserReport | None = None
        findings: list[Finding] = []
        native_counts: tuple[int | None, int | None, int | None, int | None] = (
            None,
            None,
            None,
            None,
        )

        def fail(
            stage: str, message: str, evidence: list[str], category: FailureCategory = "internal"
        ) -> None:
            failures.append(
                failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="parse"
                    if stage == "parser"
                    else "execution"
                    if stage == "scanner"
                    else "intake",
                    category=category,
                    message=message,
                    evidence=evidence,
                    partial=bool(findings),
                    affected_scope=f"agent {stage}",
                )
            )

        def invoke(
            stage: str, argv: list[str], name: str
        ) -> tuple[ProcessCapture | None, bool, list[str]]:
            assert docker is not None
            replacements = {
                snapshot.content_root: "TARGET",
                staging / "worker-source": "WORKER",
                request_path: "REQUEST",
            }
            portable = portable_docker_argv(
                argv, docker_executable=docker, mount_replacements=replacements
            )
            capture = None
            error: str | None = None
            try:
                capture = run_bounded_process(
                    argv,
                    cwd=project,
                    environment=prepared.environment,
                    timeout_seconds=profile.value.limits.timeout_seconds,
                    max_stdout_bytes=profile.value.limits.max_stdout_bytes,
                    max_stderr_bytes=profile.value.limits.max_stderr_bytes,
                )
            except OSError:
                error = "Process launch failed"
            finally:
                try:
                    cleaned = cleanup_container(
                        docker=docker,
                        container_name=name,
                        cwd=project,
                        environment=prepared.environment,
                    )
                except OSError:
                    cleaned = False
            retain(
                f"{stage}/stdout.bin",
                capture.stdout if capture else b"",
                f"{stage}-stdout",
                "application/octet-stream",
            )
            retain(
                f"{stage}/stderr.bin",
                capture.stderr if capture else b"",
                f"{stage}-stderr",
                "application/octet-stream",
            )
            receipt: JsonValue = {
                "argv": list(portable),
                "image": tool.value.validator_image if stage == "validation" else tool.value.image,
                "exit_code": capture.exit_code if capture else None,
                "launch_error": error,
                "duration_ns": capture.duration_ns if capture else 0,
                "timed_out": capture.timed_out if capture else False,
                "output_limited": capture.output_limited if capture else False,
                "stdout_truncated": capture.stdout_truncated if capture else False,
                "stderr_truncated": capture.stderr_truncated if capture else False,
                "cleanup_succeeded": cleaned,
            }
            retain(f"{stage}/receipt.json", json_bytes(receipt), f"{stage}-receipt")
            return capture, cleaned, portable

        desired = RunState.REJECTED
        outcome = ExecutionOutcome.UNSAFE_TO_RUN
        if docker is None:
            fail(
                "validation",
                "Docker unavailable; neither validation nor scanner launched",
                [],
                "missing-tool",
            )
        else:
            name = f"agent-validation-{execution_id}"
            argv = build_agent_argv(
                docker=docker,
                tool=tool.value,
                profile=profile.value,
                name=name,
                target=snapshot.content_root,
                worker_source=staging / "worker-source",
                request=request_path,
            )
            worker_capture, cleaned, _ = invoke("validation", argv, name)
            if (
                worker_capture is None
                or worker_capture.exit_code != 0
                or worker_capture.timed_out
                or worker_capture.output_limited
                or worker_capture.stderr
                or not cleaned
            ):
                fail(
                    "validation", "Input worker failed or produced incomplete/diagnostic output", []
                )
            else:
                try:
                    candidate = AgentInputReport.model_validate(
                        load_agent_json(worker_capture.stdout, max_bytes=2 * 1024 * 1024)
                    )
                    verify_input_report(candidate, worker_request, request_raw)
                    report, checks = candidate, candidate.checks
                    admission = plan_agent_input_admission(
                        [check.checked_input() for check in checks],
                        snapshot_paths=[entry.path for entry in snapshot.inventory],
                    )
                    blockers = list(admission.blockers)
                except ValueError:
                    fail(
                        "validation",
                        "Input worker response is invalid or not bound to this snapshot",
                        [],
                    )
        admitted = report is not None and not blockers
        if report is not None:
            retain("validation/report.json", model_bytes(report), "agent-input-report")
        if not admitted:
            fail(
                "admission",
                "Scanner not launched: input/policy admission was refused",
                [],
                "unsafe-target",
            )
            bundle.transition(
                RunState.REJECTED, "agent input or policy guards refused scanner admission"
            )
        else:
            assert docker is not None
            bundle.transition(
                RunState.RUNNING, "admitted authored input; restricted scanner launch"
            )
            name = f"agent-scanner-{execution_id}"
            argv = build_agent_argv(
                docker=docker,
                tool=tool.value,
                profile=profile.value,
                name=name,
                target=snapshot.content_root,
            )
            scanner_launched = True
            scanner_capture, scanner_cleanup, scanner_argv = invoke("scanner", argv, name)
            if (
                scanner_capture is None
                or scanner_capture.timed_out
                or scanner_capture.output_limited
            ):
                desired = (
                    RunState.TIMED_OUT
                    if scanner_capture and scanner_capture.timed_out
                    else RunState.EXECUTION_FAILED
                )
                outcome = (
                    ExecutionOutcome.TIMED_OUT
                    if desired == RunState.TIMED_OUT
                    else ExecutionOutcome.FAILED
                )
                fail("scanner", "Scanner failed launch or bounded capture; output retained", [])
                bundle.transition(
                    desired, "scanner execution did not produce a bounded complete capture"
                )
            else:
                native_raw = scanner_capture.stdout
                native_sha = retain("native.json", native_raw, "native-report").sha256
                bundle.transition(RunState.CAPTURED, "native bytes retained before parsing")
                bundle.transition(RunState.PARSING, "strict pinned native contract validation")
                try:
                    parsed = parse_agent_audit_json(native_raw)
                    native_semantics = native_projection(native_raw)
                    normalized = normalize_agent_audit(
                        parsed,
                        inputs=[check.checked_input() for check in checks],
                        run_id=bundle.run.run_id,
                        execution_id=execution_id,
                        target_snapshot_id=snapshot.snapshot.snapshot_id,
                    )
                    findings = sorted(
                        normalized.findings, key=lambda item: item.fingerprints.record_v1
                    )
                    native_counts = (
                        len(parsed.document.findings),
                        parsed.document.scanned_files,
                        parsed.document.summary.suppressed,
                        parsed.document.summary.by_tier["SUPPRESSED"],
                    )
                    parser_report = AgentParserReport(
                        execution_id=execution_id,
                        source_blob_sha256=native_sha,
                        parsed_at=utc_now(),
                        native_result_count=len(parsed.document.findings),
                        native_scanned_path_count=parsed.document.scanned_files,
                        normalized_finding_count=len(findings),
                        unknown_top_level_fields=list(parsed.unknown_field_paths),
                        complete=True,
                    )
                except ValueError:
                    desired, outcome = RunState.PARSE_FAILED, ExecutionOutcome.FAILED
                    fail(
                        "parser",
                        "Native evidence is invalid, incompatible or not linked to admitted inputs",
                        [native_sha],
                    )
                    bundle.transition(desired, "native parsing or normalization failed")
                else:
                    bundle.transition(
                        RunState.NORMALIZING, "native assertions retained without adjudication"
                    )
                    if scanner_capture.exit_code not in {0, 1}:
                        fail(
                            "scanner",
                            "Unexpected scanner exit code; retained evidence is partial",
                            [native_sha],
                        )
                    if scanner_capture.stderr:
                        fail(
                            "scanner",
                            "Scanner diagnostics require review; stderr retained",
                            [sha256_bytes(scanner_capture.stderr)],
                        )
                    if scanner_cleanup is not True:
                        fail("scanner", "Container cleanup not confirmed", [])
                    if parsed.document.scanned_files != len(checks):
                        fail(
                            "scanner",
                            "Native aggregate file count differs from nominated input count",
                            [native_sha],
                        )
                    # Even a matching aggregate count cannot identify which files/rules completed.
                    desired, outcome = RunState.PARTIAL, ExecutionOutcome.PARTIAL
                    bundle.transition(
                        RunState.VALIDATING, "derive reports without claiming per-file completion"
                    )
        input_unchanged = True
        for entry in snapshot.inventory:
            try:
                content = (snapshot.content_root / entry.path).read_bytes()
                unchanged = sha256_bytes(content) == entry.sha256
            except OSError:
                unchanged = False
            input_unchanged = input_unchanged and unchanged
        if not input_unchanged:
            fail(
                "validation",
                "Input snapshot changed during execution; evidence is invalid",
                [],
                "unsafe-target",
            )
            if bundle.run.state is RunState.VALIDATING:
                desired, outcome = RunState.VALIDATION_FAILED, ExecutionOutcome.FAILED
        execution = make_execution(
            execution_id=execution_id,
            run_id=bundle.run.run_id,
            snapshot=snapshot.snapshot,
            tool=tool.value,
            profile=profile.value,
            config_sha256=config_sha,
            ruleset_sha256=sha256_bytes(rules),
            portable_argv=scanner_argv,
            environment=prepared.environment,
            capture=scanner_capture,
            outcome=outcome,
            native_byte_length=len(native_raw) if native_raw is not None else 0,
            cleanup_attempted=scanner_launched,
            cleanup_succeeded=scanner_cleanup,
        )
        assessments = []
        for check in checks:
            observations = [
                finding
                for finding in findings
                if finding.locations[0].artifact_path == check.artifact.source.path
            ]
            state = "partial" if observations else "unknown" if scanner_launched else "skipped"
            assessments.append(
                AgentAssessment(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    artifact=check.artifact,
                    property_id="agent-audit.native-static-observation",
                    producer=execution.producer,
                    support="partial",
                    state=cast(AnalysisState, state),
                    finding_count=len(observations) if observations else None,
                    native_exit_code=scanner_capture.exit_code if scanner_capture else None,
                    evidence=[
                        reference for finding in observations for reference in finding.evidence
                    ],
                    reason=(
                        "Native observations only; no inference from rule ID "
                        "to the approved finite property"
                    ),
                    limitations=[
                        "Per-file completion is unobservable; no finding does not mean safe"
                    ],
                )
            )
        details = AgentRunDetails(
            run_id=bundle.run.run_id,
            execution_id=execution_id,
            target_snapshot_id=snapshot.snapshot.snapshot_id,
            case_id=case.id,
            admitted=admitted,
            blockers=blockers,
            validation_state="complete"
            if report is not None
            else "failed"
            if worker_capture
            else "not-run",
            scanner_launched=scanner_launched,
            input_unchanged=input_unchanged,
            validation_duration_ns=worker_capture.duration_ns if worker_capture else 0,
            scanner_duration_ns=scanner_capture.duration_ns if scanner_capture else 0,
            total_duration_ns=time.monotonic_ns() - started,
            native_result_count=native_counts[0],
            native_scanned_files=native_counts[1],
            native_suppressed_count=native_counts[2],
            native_tier_suppressed_count=native_counts[3],
            assessments=assessments,
            limitations=[
                "Authored development case only; no target execution or final benchmark",
                "Aggregate scanner counts do not establish per-file or per-property completion",
                "Native findings, confidence, remediation and taxonomy mappings are unreviewed",
                "Summary finding counts are stored-record counts, not a clean-scan verdict",
            ],
        )
        bundle.write_model("normalized/agent-details.json", details)
        bundle.write_model(f"{prefix}/execution.json", execution)
        if parser_report is not None:
            bundle.write_model(f"{prefix}/parser-report.json", parser_report)
        blob_index = BlobIndex(blobs=descriptors)
        bundle.write_model(f"{prefix}/blobs.json", blob_index)
        coverage = [
            CoverageRecord(
                coverage_id=new_opaque_id("coverage"),
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                target_snapshot_id=snapshot.snapshot.snapshot_id,
                property_id="agent.static-native.agent-audit",
                producer=execution.producer,
                applicability="applicable",
                adapter_support="partial",
                execution="not-run"
                if not scanner_launched
                else "partial"
                if parser_report
                else "failed",
                observation="observed-risk" if findings else "unknown",
                limitations=[*details.limitations, *blockers],
            )
        ]
        semantics = agent_semantic_document(
            config_sha=config_sha,
            target_sha=snapshot.snapshot.content_sha256,
            details=details,
            findings=findings,
            outcome=outcome,
            exit_code=execution.exit_code,
            failures=failures,
            native_document=native_semantics,
        )
        bundle.write_bytes("validation/agent-semantic.json", json_bytes(semantics))
        return finish_run(
            project_root=project,
            bundle=bundle,
            snapshot=snapshot.snapshot,
            execution=execution,
            parser_report=parser_report,
            findings=findings,
            coverage=coverage,
            failures=failures,
            blob_index=blob_index,
            desired_state=desired,
            semantic_override=semantics,
        )
