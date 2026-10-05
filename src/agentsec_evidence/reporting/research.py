"""Offline replay and reporting of one case in a sealed controlled research matrix."""

from __future__ import annotations

import json
import tomllib
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import quote

from pydantic import JsonValue, TypeAdapter

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.execution.config import ExecutionProfile
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.intake.git_verification import GitSourceVerification
from agentsec_evidence.intake.input_plan import ToolInputPlan
from agentsec_evidence.intake.views import ToolInputView, ToolViewContext
from agentsec_evidence.reporting.models import ResearchSource
from agentsec_evidence.reporting.research_models import ResearchCaseSummary, ResearchPassSummary
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.inputs import (
    assess_research_syntax,
    prepare_research_inputs,
    replay_research_inputs,
    research_worker_request,
)
from agentsec_evidence.research.models import (
    MAX_REPORT_BYTES,
    SemgrepDualView,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.retained import RetainedResearch, plain_path, read_retained_research
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass


def _json(retained: RetainedResearch, name: str) -> dict[str, Any]:
    return cast(dict[str, Any], load_agent_json(retained.read(name), max_bytes=MAX_REPORT_BYTES))


def _portable_command(argv: list[str]) -> list[str]:
    """Allow evidence relocation, not different container flags, destinations or input paths."""
    result = ["<recorded-docker>", *argv[1:]]
    for index, item in enumerate(argv):
        if index and argv[index - 1] == "--mount":
            parts = item.split(",")
            if (
                len(parts) not in {3, 4}
                or parts[0] != "type=bind"
                or not parts[1].startswith("source=")
            ):
                raise ValueError("Unexpected recorded bind mount")
            if len(parts[1]) == len("source="):
                raise ValueError("Missing recorded bind source")
            result[index] = ",".join([parts[0], "source=<retained-location>", *parts[2:]])
    return result


def _capture(retained: RetainedResearch, prefix: str) -> tuple[ProcessCapture, bool]:
    record = _json(retained, prefix + "/execution.json")
    expected = {f.name for f in fields(ProcessCapture)} - {"stdout", "stderr"}
    if set(record) != expected or not isinstance(record.get("argv"), list):
        raise ValueError("Malformed retained process capture")
    if not all(isinstance(v, str) for v in record["argv"]) or len(record["argv"]) < 2:
        raise ValueError("Malformed recorded argument array")
    for key in ("duration_ns", "peak_rss_bytes"):
        if type(record[key]) is not int or record[key] < 0:
            raise ValueError("Invalid recorded process measurement")
    for key in ("timed_out", "output_limited", "stdout_truncated", "stderr_truncated"):
        if type(record[key]) is not bool:
            raise ValueError("Invalid process status flag")
    if record["exit_code"] is not None and type(record["exit_code"]) is not int:
        raise ValueError("Invalid recorded exit code")
    command = _json(retained, prefix + "/command.json")
    if command != {"argv": record["argv"], "target_execution": False}:
        raise ValueError("Command receipt differs from process capture")
    cleanup = _json(retained, prefix + "/cleanup.json")
    if set(cleanup) != {"succeeded"} or type(cleanup["succeeded"]) is not bool:
        raise ValueError("Invalid cleanup receipt")
    for key in ("started_at", "ended_at"):
        value = datetime.fromisoformat(record[key])
        if value.utcoffset() is None:
            raise ValueError("Process timestamp requires a timezone")
        record[key] = value
    if record["ended_at"] < record["started_at"]:
        raise ValueError("Process timestamp order differs")
    record.update(
        stdout=retained.read(prefix + "/stdout.bin"), stderr=retained.read(prefix + "/stderr.bin")
    )
    return TypeAdapter(ProcessCapture).validate_python(record), cleanup["succeeded"]


def load_research_source(case_root: Path) -> tuple[ResearchSource, dict[str, JsonValue]]:
    try:
        return _load_research_source(case_root)
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError("Malformed controlled research evidence") from exc


def _load_research_source(case_root: Path) -> tuple[ResearchSource, dict[str, JsonValue]]:
    case_root = plain_path(case_root, directory=True)
    retained = read_retained_research(case_root.parent)
    case_id = case_root.name
    registry = _json(retained, "cases.json")
    if (
        registry.get("role") != "development-not-held-out"
        or registry.get("target_execution") is not False
    ):
        raise ValueError("Only declared controlled static research matrices are supported")
    cases = registry.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 100:
        raise ValueError("Invalid retained controlled case registry")
    matches = [case for case in cases if isinstance(case, dict) and case.get("id") == case_id]
    if len(matches) != 1:
        raise ValueError("Research source must identify exactly one registered case")
    case = matches[0]
    profile_bytes = retained.read("profile.json")
    profile = load_research_profile(profile_bytes)
    verify_rule_bytes(
        profile,
        {r.source_path: retained.read("rules/" + r.source_path) for r in profile.rules},
        license_bytes=retained.read("rules/LICENSE"),
    )
    context = ToolViewContext(
        ArtifactInventory.model_validate(_json(retained, f"{case_id}/inventory.json")),
        GitSourceVerification.model_validate(_json(retained, f"{case_id}/git-verification.json")),
        ToolInputPlan.model_validate(_json(retained, f"{case_id}/input-plan.json")),
        profile_bytes,
        retained.read(f"{case_id}/commit.raw"),
        retained.read(f"{case_id}/tree.json"),
    )
    if case.get("git", {}).get("revision") != context.verification.revision:
        raise ValueError("Case revision disagrees with verified source")
    parent_files = {
        f.source.path: retained.read(f"{case_id}/parent/{f.source.path}")
        for f in context.verification.files
    }
    if {p: data.decode("utf-8") for p, data in parent_files.items()} != case.get("files"):
        raise ValueError("Controlled case contents disagree with verified parent")
    selected = [s.path for s in context.plan.selections if s.disposition == "selected"]
    if sorted(selected) != sorted(case.get("selected", [])):
        raise ValueError("Controlled selected-file denominator differs")
    preparation = prepare_research_inputs(context, case_root / "parent")
    if preparation.policy.model_dump(mode="json") != _json(retained, f"{case_id}/policy.json"):
        raise ValueError("Stored research policy differs from full-parent replay")
    passes: list[ResearchPassSummary] = []
    duals: list[SemgrepDualView] = []
    native_runs: dict[str, dict[str, Any]] = {}
    state: Literal["policy-refused", "syntax-refused", "observed"] = "policy-refused"
    syntax_state: Literal["not-run", "rejected", "parsed"] = "not-run"
    expected_passes: set[str] = set()
    if preparation.scope is not None:
        scope = preparation.scope
        if scope.model_dump(mode="json") != _json(retained, f"{case_id}/view/scope.json"):
            raise ValueError("Stored selected scope differs from replay")
        if preparation.policy.model_dump(mode="json") != _json(
            retained, f"{case_id}/view/policy.json"
        ):
            raise ValueError("Mounted-view policy differs from full-parent replay")
        replay_research_inputs(
            context,
            source=case_root / "parent",
            preparation=preparation,
            view=ToolInputView.model_validate(_json(retained, f"{case_id}/view/view.json")),
            target=case_root / "view/target",
        )
        request = research_worker_request(scope)
        request_bytes = retained.read(f"{case_id}/request.json")
        if request != AgentInputRequest.model_validate_json(request_bytes):
            raise ValueError("Syntax request differs from selected scope")
        capture, cleaned = _capture(retained, f"{case_id}/syntax")
        limits = ExecutionProfile.model_validate(
            tomllib.loads(retained.read("execution-profile.toml").decode())
        )
        tool = AgentAuditToolConfig.model_validate(
            tomllib.loads(retained.read("validator-tool.toml").decode())
        )
        name = capture.argv[capture.argv.index("--name") + 1]
        expected = build_agent_argv(
            docker=retained.root / "profile.json",
            tool=tool,
            profile=limits,
            name=name,
            target=case_root / "view/target",
            worker_source=retained.root / "worker-source",
            request=case_root / "request.json",
        )
        if _portable_command(list(capture.argv)) != _portable_command(expected):
            raise ValueError("Recorded syntax invocation differs from guarded treatment")
        if (
            capture.exit_code != 0
            or capture.timed_out
            or capture.output_limited
            or capture.stdout_truncated
            or capture.stderr_truncated
            or not cleaned
        ):
            raise ValueError("Incomplete syntax worker is not an admitted retained case")
        parsed = assess_research_syntax(request, request_bytes, capture.stdout)
        syntax_state, state = ("parsed", "observed") if parsed else ("rejected", "syntax-refused")
        if parsed:
            repetitions = 2 if case.get("repeat") is True else 1
            for repetition in range(1, repetitions + 1):
                pair = []
                for role in ("research", "repository-policy"):
                    role_value: Literal["research", "repository-policy"] = (
                        "research" if role == "research" else "repository-policy"
                    )
                    key = f"{role}-{repetition}"
                    expected_passes.add(key)
                    prefix = f"{case_id}/{key}"
                    process, cleaned = _capture(retained, prefix)
                    name = process.argv[process.argv.index("--name") + 1]
                    expected = build_research_argv(
                        docker=Path(process.argv[0]),
                        name=name,
                        profile_bytes=profile_bytes,
                        scope=scope,
                        role=role_value,
                        rules=retained.root / "rules",
                        target=case_root / "view/target",
                        output=case_root / key,
                    )
                    if _portable_command(list(process.argv)) != _portable_command(expected):
                        raise ValueError(
                            "Recorded scanner invocation differs from guarded treatment"
                        )
                    evidence = reconcile_semgrep_pass(
                        profile_bytes=profile_bytes,
                        scope=scope,
                        execution_id=name,
                        role=role_value,
                        native_json=retained.read(prefix + "/native.json"),
                        native_sarif=retained.read(prefix + "/native.sarif"),
                    )
                    assessment = assess_research_execution(
                        process, cleanup_succeeded=cleaned, evidence=evidence
                    )
                    if evidence.model_dump(mode="json") != _json(
                        retained, prefix + "/evidence.json"
                    ) or assessment.model_dump(mode="json") != _json(
                        retained, prefix + "/assessment.json"
                    ):
                        raise ValueError("Stored native or process derivative differs from replay")
                    native_runs[key] = _json(retained, prefix + "/native.sarif")["runs"][0]
                    passes.append(
                        ResearchPassSummary(
                            key=key,
                            repetition=repetition,
                            evidence=evidence,
                            execution=assessment,
                            exit_code=process.exit_code,
                            duration_ns=process.duration_ns,
                            native_finding_records=len(evidence.findings),
                            native_json_path=prefix + "/native.json",
                            native_sarif_path=prefix + "/native.sarif",
                        )
                    )
                    pair.append(evidence)
                dual = build_dual_view(*pair)
                if dual.model_dump(mode="json") != _json(
                    retained, f"{case_id}/dual-view-{repetition}.json"
                ):
                    raise ValueError("Stored policy view differs from replay")
                duals.append(dual)
    actual_passes = {
        p.split("/")[1]
        for p in retained.files
        if p.startswith(case_id + "/")
        and p.split("/")[1].startswith(("research-", "repository-policy-"))
    }
    if actual_passes != expected_passes:
        raise ValueError("Unaccounted or missing research scanner attempts")
    if preparation.scope is None and any(
        p.startswith(f"{case_id}/syntax/") for p in retained.files
    ):
        raise ValueError("Refused policy cannot claim a syntax-worker invocation")
    summary = ResearchCaseSummary(
        case_id=case_id,
        state=state,
        selected_file_count=len(selected),
        policy=preparation.policy,
        scope=preparation.scope,
        syntax_state=syntax_state,
        passes=tuple(passes),
        dual_views=tuple(duals),
    )
    source = ResearchSource(
        run_id="research-"
        + semantic_hash({"manifest": retained.manifest_sha256, "case": case_id})[:32],
        state=state,
        label=context.inventory.snapshot.source_label,
        revision=context.verification.revision,
        target_content_sha256=context.inventory.snapshot.content_sha256,
        source_manifest_sha256=retained.manifest_sha256,
        source_semantic_sha256=None,
        summary=summary,
    )
    return source, research_sarif(source, native_runs)


def research_sarif(
    source: ResearchSource, native_runs: dict[str, dict[str, Any]]
) -> dict[str, JsonValue]:
    runs: list[dict[str, Any]] = []
    base = {
        "agentsecEvidence/sourceRunId": source.run_id,
        "agentsecEvidence/sourceManifestSha256": source.source_manifest_sha256,
        "agentsecEvidence/researchCase": source.summary.case_id,
        "agentsecEvidence/evidenceRole": source.summary.evidence_role,
        "agentsecEvidence/policyLabel": source.summary.policy.label,
    }
    for row in source.summary.passes:
        native = native_runs[row.key]
        results = []
        for finding in row.evidence.findings:
            index = int(finding.sarif_pointer.rsplit("/", 1)[1])
            result = json.loads(json.dumps(native["results"][index]))
            physical = result["locations"][0]["physicalLocation"]
            physical["artifactLocation"] = {"uri": quote(finding.anchor.path, safe="/")}
            result["kind"] = "review"
            result["partialFingerprints"] = {
                "agentsecEvidence/researchAnchor/v1": semantic_hash(
                    {
                        "target": source.target_content_sha256,
                        "profile": row.evidence.profile_sha256,
                        "anchor": finding.anchor.model_dump(mode="json"),
                    }
                )
            }
            result.setdefault("properties", {}).update(
                {
                    "agentsecEvidence/reviewState": "unreviewed",
                    "agentsecEvidence/nativeSuppressions": list(finding.native_suppressions),
                    "agentsecEvidence/nativeJsonPath": row.native_json_path,
                    "agentsecEvidence/nativeJsonSha256": row.evidence.native_json_sha256,
                    "agentsecEvidence/nativeJsonPointer": finding.json_pointer,
                    "agentsecEvidence/nativeSarifPath": row.native_sarif_path,
                    "agentsecEvidence/nativeSarifSha256": row.evidence.native_sarif_sha256,
                    "agentsecEvidence/nativeSarifPointer": finding.sarif_pointer,
                }
            )
            if finding.native_suppressions:
                result["suppressions"] = [
                    {
                        "kind": s["kind"],
                        "status": "underReview",
                        "justification": (
                            "Native suppression retained; not approved by this platform"
                        ),
                    }
                    for s in finding.native_suppressions
                ]
            results.append(result)
        notification = (
            "Recorded analysis remains "
            + row.execution.analysis_state
            + "; complete rule coverage is not established."
        )
        runs.append(
            {
                "tool": native["tool"],
                **({"columnKind": native["columnKind"]} if "columnKind" in native else {}),
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": row.execution.analysis_state != "failed"
                        and row.exit_code == 0,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": notification}}
                        ],
                    }
                ],
                "properties": {
                    **base,
                    "agentsecEvidence/researchPass": row.key,
                    "agentsecEvidence/analysisState": row.execution.analysis_state,
                    "agentsecEvidence/nativeExecutionSuccessful": (
                        row.evidence.native_execution_successful
                    ),
                    "agentsecEvidence/nativeExitCode": row.exit_code,
                },
            }
        )
    if not runs:
        runs.append(
            {
                "tool": {"driver": {"name": "agentsec-evidence research input gate"}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": False,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {
                                    "text": source.state
                                    + "; scanner not run. Finding count is unknown, not zero."
                                },
                            }
                        ],
                    }
                ],
                "properties": {
                    **base,
                    "agentsecEvidence/researchPass": "not-run",
                    "agentsecEvidence/analysisState": source.state,
                    "agentsecEvidence/scannerLaunched": False,
                },
            }
        )
    return cast(
        dict[str, JsonValue], {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": runs}
    )


def validate_research_runs(source: ResearchSource, runs: list[dict[str, JsonValue]]) -> None:
    """Check derivative correspondence; original raw evidence is reopened only at build time."""
    values = cast(list[dict[str, Any]], runs)
    by_key = {run.get("properties", {}).get("agentsecEvidence/researchPass"): run for run in values}
    expected = [row.key for row in source.summary.passes] or ["not-run"]
    if len(by_key) != len(values) or set(by_key) != set(expected):
        raise ValueError("Research passes were omitted, duplicated or combined")
    for run in values:
        props = run["properties"]
        if (
            props.get("agentsecEvidence/researchCase") != source.summary.case_id
            or props.get("agentsecEvidence/policyLabel") != source.summary.policy.label
            or props.get("agentsecEvidence/evidenceRole") != source.summary.evidence_role
        ):
            raise ValueError("Research case or policy label differs")
    if not source.summary.passes:
        run = by_key["not-run"]
        if (
            run["results"]
            or run["invocations"][0]["executionSuccessful"] is not False
            or run["properties"].get("agentsecEvidence/scannerLaunched") is not False
            or run["properties"].get("agentsecEvidence/analysisState") != source.state
        ):
            raise ValueError("Refused research input cannot be a successful no-finding scan")
        return
    for row in source.summary.passes:
        run = by_key[row.key]
        props = run["properties"]
        if (
            len(run["results"]) != row.native_finding_records
            or props.get("agentsecEvidence/analysisState") != row.execution.analysis_state
            or props.get("agentsecEvidence/nativeExitCode") != row.exit_code
            or props.get("agentsecEvidence/nativeExecutionSuccessful")
            != row.evidence.native_execution_successful
        ):
            raise ValueError("Research result or execution accounting differs")
        if run["invocations"][0]["executionSuccessful"] != (
            row.execution.analysis_state != "failed" and row.exit_code == 0
        ):
            raise ValueError("Research invocation outcome differs")
        for result, finding in zip(run["results"], row.evidence.findings, strict=True):
            physical = result["locations"][0]["physicalLocation"]
            anchor = finding.anchor
            expected_region = {
                "startLine": anchor.start_line,
                "startColumn": anchor.start_column,
                "endLine": anchor.end_line,
                "endColumn": anchor.end_column,
            }
            if (
                result.get("ruleId") != anchor.rule_id
                or result.get("kind") != "review"
                or result["message"].get("text") != finding.message
                or physical["artifactLocation"].get("uri") != quote(anchor.path, safe="/")
                or any(physical["region"].get(k) != v for k, v in expected_region.items())
            ):
                raise ValueError("Research result differs from its evidence anchor")
            props = result.get("properties", {})
            if result.get("partialFingerprints") != {
                "agentsecEvidence/researchAnchor/v1": semantic_hash(
                    {
                        "target": source.target_content_sha256,
                        "profile": row.evidence.profile_sha256,
                        "anchor": anchor.model_dump(mode="json"),
                    }
                )
            }:
                raise ValueError("Research finding fingerprint differs from its anchor")
            references = {
                "reviewState": "unreviewed",
                "nativeSuppressions": list(finding.native_suppressions),
                "nativeJsonPath": row.native_json_path,
                "nativeJsonSha256": row.evidence.native_json_sha256,
                "nativeJsonPointer": finding.json_pointer,
                "nativeSarifPath": row.native_sarif_path,
                "nativeSarifSha256": row.evidence.native_sarif_sha256,
                "nativeSarifPointer": finding.sarif_pointer,
            }
            if any(props.get("agentsecEvidence/" + k) != v for k, v in references.items()):
                raise ValueError("Research native evidence linkage differs")
            expected_suppression = [
                {
                    "kind": s["kind"],
                    "status": "underReview",
                    "justification": "Native suppression retained; not approved by this platform",
                }
                for s in finding.native_suppressions
            ]
            if result.get("suppressions", []) != expected_suppression:
                raise ValueError("Native suppression cannot become reviewer approval")
