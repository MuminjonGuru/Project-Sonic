"""Rehearse common reporting from seven sealed repair bundles, without scanning."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.custom import load_custom_source
from agentsec_evidence.reporting.custom_contracts import FAMILIES, catalog
from agentsec_evidence.reporting.custom_models import CustomCommonReport, CustomSource
from agentsec_evidence.reporting.service import validate_common_report, write_common_report
from agentsec_evidence.research.retained import plain_path

ROOT = Path(__file__).resolve().parents[1]
BUNDLES = (
    "tool_execution_shared_ast",
    "network_data_repair",
    "filesystem_repair",
    "memory_state_repair",
    "self_modification_repair",
    "orchestration_repair",
    "agent_to_agent_repair",
)


def save(path: Path, value: Any) -> None:
    with path.open("xb") as handle:
        handle.write(json_bytes(value))


def file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def rehearse(output: Path) -> None:
    for parent in [output, *output.parents]:
        if parent.is_symlink() or parent.is_junction():
            raise ValueError("Rehearsal destination cannot contain a filesystem link")
    output = output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "outputs"):
        raise ValueError("Use a new destination below Project_Development/outputs")
    bundles = [ROOT / "outputs" / f"{name}_2026-10-20-final" for name in BUNDLES]
    if any(output.is_relative_to(bundle) for bundle in bundles):
        raise ValueError("Rehearsal cannot modify source evidence")
    before = {}
    for bundle in bundles:
        plain_path(bundle, directory=True)
        load_custom_source(ROOT, bundle)
        before[bundle.name] = file_hashes(bundle)
    output.mkdir(parents=True, exist_ok=False)
    save(output / "source-evidence-before.json", before)

    builds = []
    reports = []
    for label in ("build-1", "build-2"):
        started = perf_counter_ns()
        report = write_common_report(project_root=ROOT, bundles=bundles, output=output / label)
        duration = perf_counter_ns() - started
        if not isinstance(report, CustomCommonReport):
            raise ValueError("Expected additive custom reporting contract")
        reports.append(report)
        builds.append(
            {
                "report": label,
                "report_build_duration_ns": duration,
                "validation": validate_common_report(ROOT, output / label),
            }
        )
    if reports[0].model_dump(exclude={"generated_at"}) != reports[1].model_dump(
        exclude={"generated_at"}
    ):
        raise ValueError("Repeated report content differs beyond generation timestamp")
    if (output / "build-1/results.sarif").read_bytes() != (
        output / "build-2/results.sarif"
    ).read_bytes():
        raise ValueError("Repeated SARIF bytes differ")
    shutil.copytree(output / "build-1", output / "relocated-copy")
    relocation = validate_common_report(ROOT, output / "relocated-copy")

    rows: list[dict[str, Any]] = []
    for source in reports[0].sources:
        if not isinstance(source, CustomSource):
            raise ValueError("Unexpected nonrepair source in rehearsal")
        rules = catalog(source.summary.treatments[0].native)
        rows.extend(
            {
                "family": source.summary.family,
                "treatment": row.key,
                "source_run_id": source.run_id,
                "source_manifest_sha256": source.source_manifest_sha256,
                "selected_files": len(row.request.selected),
                "analyzed_files": sum(f.state == "analyzed" for f in row.native.files),
                "incomplete_files": sum(f.findings is None for f in row.native.files),
                "native_condition_records": sum(len(f.findings or []) for f in row.native.files),
                "inventory_observations": sum(len(f.inventory) for f in row.native.files),
                "limitation_observations": sum(
                    len(f.limitations_observed) for f in row.native.files
                ),
                "catalog_active_conditions": sum(r["status"] == "active-condition" for r in rules),
                "catalog_inventory_only": sum(r["status"] == "inventory-only" for r in rules),
                "catalog_deferred": sum(r["status"] == "deferred" for r in rules),
                "execution_state": row.native.execution_state,
                "native_exit_code": row.exit_code,
                "retained_worker_duration_ns": row.duration_ns,
                "native_sha256": row.stdout_sha256,
                "unique_vulnerabilities": None,
            }
            for row in source.summary.treatments
        )
    if before != {bundle.name: file_hashes(bundle) for bundle in bundles}:
        raise ValueError("Reporting modified retained evidence")
    save(output / "rows.json", rows)
    implementation = {
        path.relative_to(ROOT).as_posix(): sha256_file(path)
        for path in sorted((ROOT / "src/agentsec_evidence/reporting").glob("*.py"))
    }
    for relative in (
        "tools/verify_custom_reporting.py",
        "tests/integration/test_custom_reporting.py",
        "schemas/reporting-v5/common-report.schema.json",
        "src/agentsec_evidence/scoring/measurements.py",
    ):
        implementation[relative] = sha256_file(ROOT / relative)
    save(output / "reporting-implementation.json", implementation)
    save(
        output / "verification.json",
        {
            "contract": "custom-reporting-rehearsal-v1",
            "passed": True,
            "sources": len(FAMILIES),
            "treatments": len(rows),
            "native_scanner_launches": 0,
            "new_public_targets": 0,
            "source_evidence_files_verified_unchanged": sum(len(v) for v in before.values()),
            "builds": builds,
            "report_semantics_equal_excluding": ["generated_at"],
            "sarif_bytes_equal": True,
            "same_host_relocated_derivative": relocation,
            "native_request_text_preserved": True,
            "native_report_text_preserved": True,
            "independent_replication": False,
            "html_support": "not-yet-supported-for-v5",
            "benchmark_admission": "not-granted-for-custom-repair",
            "unique_vulnerabilities": None,
        },
    )
    lines = [
        "# Seven-Family Reporting Rehearsal",
        "",
        "20 October 2026. Offline derivation from existing authored development evidence.",
        "No fresh scanner, public repository, target execution or installation was run.",
        "Different families use different fixtures. This is not a same-repository comparison,",
        "held-out evaluation, independent accuracy study or confirmed-vulnerability count.",
        "",
        "## First Full Treatment Per Family",
        "",
        "| Family | Active / inventory / deferred IDs | Selected / analyzed files | "
        "Condition records | Inventory observations | State |",
        "|---|---:|---:|---:|---:|---|",
    ]
    lines.extend(
        f"| {row['family']} | {row['catalog_active_conditions']} / "
        f"{row['catalog_inventory_only']} / {row['catalog_deferred']} | "
        f"{row['selected_files']} / {row['analyzed_files']} | "
        f"{row['native_condition_records']} | {row['inventory_observations']} | "
        f"{row['execution_state']} |"
        for row in rows
        if row["treatment"] == "all-repeat-1"
    )
    lines += [
        "",
        "Each full treatment deliberately includes malformed input; partial is not clean.",
        "The four treatments per family remain separate: two full repetitions, valid-only",
        "input and corrected/benign controls. Every row and retained duration is in",
        "[rows.json](rows.json). Do not pool repetitions, inventory or overlapping rules.",
        "",
        "## Evidence",
        "",
        "- [Combined native-preserving report](build-1/report.json): internal, unredacted.",
        "- [Condition-only SARIF](build-1/results.sarif): line locations and original byte ranges;",
        "  no source snippets, calibrated severity or invented column conversion.",
        "- [Rehearsal receipt](verification.json): two equivalent builds; SARIF byte-identical;",
        "  same-host derivative relocation passed; original sealed evidence unchanged.",
        "- [Source receipts](source-evidence-before.json) and",
        "  [reporting implementation](reporting-implementation.json) retain provenance.",
        "",
        "Native priority is uncalibrated; SARIF warning does not prove exploitability.",
        "Suppression comments/local ignores were not applied. All native identities remain",
        "separate; unique-vulnerability counts are unknown. Inventory-only families contribute",
        "zero condition results, not a conclusion that their subjects are secure.",
        "",
        "## Next Boundary",
        "",
        "Custom-family HTML presentation, a frozen common-input execution profile, overlap",
        "review and suppression-policy tests precede separately admitted public scanning.",
        "Old public-pilot and HTML evidence remains unchanged. This rehearsal adds no scan",
        "permission, publication approval, independent labels or final research claims.",
    ]
    (output / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    save(output / "manifest.json", file_hashes(output))
    print(json.dumps({"output": str(output), "sources": 7, "treatments": len(rows)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    rehearse(parser.parse_args().output)
