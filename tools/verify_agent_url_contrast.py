"""Run only the four approved static URL contrasts; preserve disagreements, not tune rules."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.agents.bundle_validation import validate_agent_bundle
from agentsec_evidence.agents.url_contrast import (
    CASE_IDS,
    CASE_SET,
    REGISTRY,
    REGISTRY_SHA256,
    RULE_ID,
    describe_rule_observation,
    load_url_contrast_case,
)
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.models.contracts import RunState
from agentsec_evidence.operations.offline import load_existing_run
from agentsec_evidence.orchestration.agent_pipeline import AgentScanRequest, run_agent_scan
from agentsec_evidence.reporting.service import validate_common_report, write_common_report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New child of workspace/")
    parser.add_argument("--repetitions", type=int, choices=(1, 2, 3), default=2)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if not output.is_relative_to(project / "workspace") or output == project / "workspace":
        raise ValueError("Contrast evidence must use a new directory beneath this workspace")
    cases = [load_url_contrast_case(project, case_id)[0] for case_id in CASE_IDS]
    frozen_paths = [
        project / REGISTRY,
        project / "configs/tools/agent-audit.toml",
        project / "configs/profiles/agent-development.toml",
        Path(__file__).resolve(),
        *sorted((project / "src").rglob("*.py")),
    ]
    pins = {p.relative_to(project).as_posix(): sha256_file(p) for p in frozen_paths}
    output.mkdir(parents=True, exist_ok=False)
    atomic_write_bytes(
        output / "plan.json",
        json_bytes(
            {
                "case_set": CASE_SET,
                "role": "development-not-held-out",
                "case_ids": list(CASE_IDS),
                "repetitions": args.repetitions,
                "registry_sha256": REGISTRY_SHA256,
                "pins": cast(JsonValue, pins),
                "named_claim_rule": RULE_ID,
                "target_execution": False,
                "independent_review": False,
                "semantics": "agent-run-semantic-v1; native rule disagreements are outcomes",
            }
        ),
    )
    rows: list[dict[str, JsonValue]] = []
    bundles: list[Path] = []
    workspace = output / "workspace"
    for repetition in range(1, args.repetitions + 1):
        for case in cases:
            if any(sha256_file(project / name) != digest for name, digest in pins.items()):
                raise ValueError(
                    "Frozen implementation, fixture or treatment changed; new run required"
                )
            attempt = output / "attempts" / f"r{repetition}-{case.id}"
            attempt.mkdir(parents=True, exist_ok=False)
            atomic_write_bytes(
                attempt / "start.json",
                json_bytes({"case": case.id, "repetition": repetition, "retry": False}),
            )
            result = run_agent_scan(AgentScanRequest(project, workspace, case.id))
            existing = load_existing_run(workspace, result.run_id)
            details = validate_agent_bundle(existing)
            available = (
                result.terminal_state == RunState.PARTIAL
                and details.admitted
                and details.scanner_launched
                and details.input_unchanged
                and existing.parser_report is not None
                and not existing.failures
            )
            rules = [f.rule.native_id for f in existing.findings] if available else None
            row: dict[str, JsonValue] = {
                "case": case.id,
                "repetition": repetition,
                "expected_source_condition": case.expected_condition,
                "state": result.terminal_state.value,
                "observation": describe_rule_observation(case.expected_condition, rules),
                "native_rules": cast(JsonValue, rules),
                "named_rule_reports": rules.count(RULE_ID) if rules is not None else None,
                "native_report_count": details.native_result_count,
                "native_scanned_files": details.native_scanned_files,
                "analysis_completeness": "not-established",
                "run_id": result.run_id,
                "semantic_sha256": result.semantic_sha256,
                "manifest_sha256": sha256_file(existing.root / "bundle-manifest.json"),
                "total_duration_ns": details.total_duration_ns,
                "evidence": existing.root.relative_to(output).as_posix(),
            }
            atomic_write_bytes(attempt / "finish.json", json_bytes(row))
            rows.append(row)
            bundles.append(existing.root)
            atomic_write_bytes(output / "progress.json", json_bytes(cast(JsonValue, rows)))
            print(json.dumps(row), flush=True)
            if not available:
                raise RuntimeError(
                    "Unassessable execution retained; not counted as a negative result"
                )
    repeatability = {
        case_id: (
            len({r["semantic_sha256"] for r in rows if r["case"] == case_id}) == 1
            if args.repetitions > 1
            else None
        )
        for case_id in CASE_IDS
    }
    write_common_report(project_root=project, bundles=bundles, output=output / "common-report")
    validate_common_report(project, output / "common-report")
    csv_buffer = io.StringIO(newline="")
    columns = [
        "case",
        "repetition",
        "expected_source_condition",
        "observation",
        "named_rule_reports",
        "native_report_count",
        "state",
        "semantic_sha256",
        "evidence",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    atomic_write_bytes(output / "comparison.csv", csv_buffer.getvalue().encode("utf-8"))
    lines = [
        "# Request-URL Source-Condition Contrast",
        "",
        "Authored development family; not held-out data, public accuracy or exploitability.",
        "",
        "Expected conditions were frozen before execution. The original analyzer is unchanged.",
        "Rule reports on absent-condition cases are claim/condition discrepancies, not a measured",
        "general false-positive rate. No report does not prove complete analysis or safety.",
        "",
        "| Case | Repeat | Expected source condition | AGENT-026 reports | Observation |",
        "|---|---:|---|---:|---|",
    ]
    lines.extend(
        f"| {r['case']} | {r['repetition']} | {r['expected_source_condition']} | "
        f"{r['named_rule_reports']} | {r['observation']} |"
        for r in rows
    )
    lines.extend(["", "## Repeatability", ""])
    lines.extend(f"- {case_id}: {same}" for case_id, same in repeatability.items())
    lines.extend(
        [
            "",
            "All native records remain in the linked bundles. Eight observations from two repeats",
            "would still be four related development cases, not eight independent samples.",
            "Redirects, effective egress, credentials and runtime invocation were not tested.",
            "No target code was executed and no vulnerability adjudication is implied.",
            "",
        ]
    )
    atomic_write_bytes(output / "REVIEW.md", "\n".join(lines).encode("utf-8"))
    atomic_write_bytes(
        output / "matrix.json",
        json_bytes(
            {
                "case_set": CASE_SET,
                "workflow_completed": True,
                "security_analysis_complete": False,
                "independent_adjudication": False,
                "repeatability": cast(JsonValue, repeatability),
                "rows": cast(JsonValue, rows),
            }
        ),
    )
    if any(sha256_file(project / name) != digest for name, digest in pins.items()):
        raise ValueError("Frozen inputs changed during execution; retained results require review")
    entries: list[JsonValue] = [
        {
            "path": path.relative_to(output).as_posix(),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    ]
    atomic_write_bytes(output / "evidence-manifest.json", json_bytes({"entries": entries}))
    if any(value is False for value in repeatability.values()):
        raise RuntimeError(
            "Semantic repeatability disagreement retained; do not claim stable output"
        )


if __name__ == "__main__":
    main()
