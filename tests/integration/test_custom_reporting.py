"""Synthetic adapter tests using only authored cases; not Docker/accuracy evidence."""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.reporting.custom import _CONTROLS, load_custom_source
from agentsec_evidence.reporting.custom_contracts import (
    FAMILIES,
    IMAGE,
    TREATMENTS,
    Family,
    expected_exit,
)
from agentsec_evidence.reporting.custom_models import CustomCommonReport
from agentsec_evidence.reporting.presentation import read_presentation_inputs
from agentsec_evidence.reporting.service import (
    parse_common_report,
    validate_common_report,
    write_common_report,
)
from tools.verify_tool_execution_repair import docker_argv

ROOT = Path(__file__).resolve().parents[2]


def put(root: Path, name: str, value: Any) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        value
        if isinstance(value, bytes)
        else (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    )


def read(root: Path, name: str) -> Any:
    return json.loads((root / name).read_bytes())


def seal(root: Path) -> None:
    put(
        root,
        "manifest.json",
        {
            p.relative_to(root).as_posix(): sha256_file(p)
            for p in sorted(root.rglob("*"))
            if p.is_file() and p.name != "manifest.json"
        },
    )


def synthetic_bundle(root: Path, family: Family) -> Path:
    root.mkdir(parents=True)
    paths = family.critical_sources | {family.registry, "tools/" + family.helper}
    implementation = {path: sha256_file(ROOT / path) for path in sorted(paths)}
    for path in paths:
        put(root, "source-snapshot/" + path, (ROOT / path).read_bytes())
    put(root, "implementation.json", implementation)
    registry = read(ROOT, family.registry)
    target = root / "input"
    for case in registry["cases"]:
        put(target, case["id"] + ".py", case["source"].encode())
    # Trusted authored fixture source only. Production reporting must never call scan_view.
    worker = importlib.import_module("agentsec_evidence.custom_rules." + family.worker)
    from agentsec_evidence.models.contracts import InventoryEntry

    inventory = [
        InventoryEntry(
            path=p.name,
            sha256=sha256_file(p),
            byte_length=p.stat().st_size,
            media_type="text/x-python",
        )
        for p in sorted(target.iterdir())
    ]
    rows = []
    for key in TREATMENTS:
        cases = registry["cases"]
        if key == "valid-only":
            cases = [c for c in cases if c["rules"] is not None]
        elif key == "corrected-controls":
            cases = [c for c in cases if c["id"] in _CONTROLS[family.key]]
        request = AgentInputRequest(
            target_snapshot_id="development-" + family.key + "-v1",
            inventory=inventory,
            selected={c["id"] + ".py": "python-source" for c in cases},
        )
        request_bytes = request.model_dump_json().encode() + b"\n"
        native = worker.scan_view(target, request_bytes)
        raw = native.model_dump_json().encode() + b"\n"
        argv = docker_argv(
            "synthetic-" + key, target, root / key / "request.json", root / "source-snapshot/src"
        )
        argv[argv.index("agentsec_evidence.custom_rules.tool_execution_worker")] = (
            "agentsec_evidence.custom_rules." + family.worker
        )
        argv[-1] = family.threshold
        put(root, key + "/request.json", request_bytes)
        put(root, key + "/stdout.json", raw)
        put(root, key + "/stderr.txt", b"")
        put(root, key + "/process.json", {"exit_code": expected_exit(native), "duration_ns": 100})
        put(root, key + "/invocation.json", {"argv": argv, "expected_exit": expected_exit(native)})
        row = {
            "treatment": key,
            "selected_files": len(cases),
            "execution_state": native.execution_state,
            "native_findings": sum(len(file.findings or []) for file in native.files),
            "files_with_unknown_or_unsupported_constructs": sum(
                bool(file.limitations_observed) for file in native.files
            ),
            "exit_code": expected_exit(native),
            "duration_ns": 100,
            "stdout_sha256": sha256_bytes(raw),
        }
        if family.key != "tool-execution":
            row["inventory_rule_observations"] = sum(
                getattr(item, "rule_id", None) is not None
                for file in native.files
                for item in file.inventory
            )
        rows.append(row)
    put(root, "image-inspect.stdout.json", [{"Id": IMAGE}])
    put(root, "image-inspect.stderr.txt", b"")
    put(
        root,
        "verification.json",
        {
            "contract": family.key + "-repair-verification-v1",
            "registry_sha256": sha256_file(ROOT / family.registry),
            "image_id": IMAGE,
            "case_count": len(registry["cases"]),
            "repeated_native_bytes_equal": True,
            "rows": rows,
        },
    )
    seal(root)
    return root


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    return synthetic_bundle(tmp_path / "input-evidence", FAMILIES[0])


@pytest.mark.parametrize("family", FAMILIES, ids=lambda f: f.key)
def test_all_seven_families_preserve_units(tmp_path: Path, family: Family) -> None:
    bundle = synthetic_bundle(tmp_path / family.key, family)
    source, sarif = load_custom_source(ROOT, bundle)
    runs = cast(list[dict[str, Any]], sarif["runs"])
    assert source.summary.family == family.key
    assert source.summary.vulnerability_total is None
    assert [row.key for row in source.summary.treatments] == list(TREATMENTS)
    for row, run in zip(source.summary.treatments, runs, strict=True):
        assert len(run["results"]) == sum(len(file.findings or []) for file in row.native.files)
        assert row.unique_vulnerabilities is None and row.review_grouping == "not-performed"
        assert row.suppression_application == "not-applied"
        assert run["properties"]["agentsecEvidence/unparsedFiles"] == [
            file.path for file in row.native.files if file.findings is None
        ]
    if family.key in {"agent-to-agent", "orchestration"}:
        assert all(not run["results"] for run in runs)
        assert source.summary.treatments[0].native.files
        assert any(file.inventory for file in source.summary.treatments[0].native.files)
    output = tmp_path / "common"
    report = write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    assert isinstance(report, CustomCommonReport)
    assert validate_common_report(ROOT, output)["passed"]
    assert parse_common_report((output / "report.json").read_bytes()) == report


def test_report_does_not_rescan_or_launch_processes(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Reporting attempted scanner execution")

    monkeypatch.setattr(subprocess, "run", fail)
    for family in FAMILIES:
        worker = importlib.import_module("agentsec_evidence.custom_rules." + family.worker)
        monkeypatch.setattr(worker, "scan_view", fail)
    write_common_report(project_root=ROOT, bundles=[bundle], output=tmp_path / "report")


@pytest.mark.parametrize(
    "mutation",
    [
        "raw-drift",
        "extra-file",
        "empty-directory",
        "missing-output",
        "traversal",
        "duplicate-key",
        "catalog",
        "request-binding",
        "input",
        "exit-status",
        "stderr",
        "network-enabled",
        "writable-target",
        "wrong-worker",
        "wrong-image",
        "wrong-count",
        "wrong-pin",
        "selection",
        "suppression-policy",
        "extra-ignore",
        "drop-finding",
        "priority",
        "native-id",
        "range",
        "refusal-masquerades-clean",
    ],
)
def test_tampering_refused_even_after_resealing(bundle: Path, mutation: str) -> None:
    key = "all-repeat-1"
    if mutation == "raw-drift":
        (bundle / key / "stdout.json").write_bytes(b"{}")
        with pytest.raises(ValueError):
            load_custom_source(ROOT, bundle)
        return
    if mutation == "extra-file":
        put(bundle, "extra.txt", b"unexpected")
    elif mutation == "empty-directory":
        (bundle / "extra").mkdir()
    elif mutation == "missing-output":
        (bundle / key / "stdout.json").unlink()
    elif mutation == "traversal":
        manifest = read(bundle, "manifest.json")
        manifest["../escape"] = "a" * 64
        put(bundle, "manifest.json", manifest)
        with pytest.raises(ValueError):
            load_custom_source(ROOT, bundle)
        return
    elif mutation == "duplicate-key":
        put(bundle, "verification.json", b'{"contract":"x","contract":"y"}')
    elif mutation == "input":
        path = next((bundle / "input").iterdir())
        path.write_bytes(b"# nosemgrep\n")
    elif mutation == "stderr":
        put(bundle, key + "/stderr.txt", b"worker error")
    elif mutation == "exit-status":
        put(bundle, key + "/process.json", {"exit_code": 0, "duration_ns": 100})
    elif mutation in {"network-enabled", "writable-target", "wrong-worker"}:
        invocation = read(bundle, key + "/invocation.json")
        argv = invocation["argv"]
        if mutation == "network-enabled":
            argv[argv.index("--network") + 1] = "host"
        elif mutation == "writable-target":
            index = next(i for i, item in enumerate(argv) if "dst=/target" in item)
            argv[index] = argv[index].replace(",readonly", "")
        else:
            argv[argv.index("-m") + 1] = "arbitrary_plugin"
        put(bundle, key + "/invocation.json", invocation)
    elif mutation == "wrong-image":
        put(bundle, "image-inspect.stdout.json", [{"Id": "other"}])
    elif mutation == "wrong-count":
        value = read(bundle, "verification.json")
        value["rows"][0]["native_findings"] += 1
        put(bundle, "verification.json", value)
    elif mutation == "wrong-pin":
        value = read(bundle, "implementation.json")
        value[FAMILIES[0].registry] = "b" * 64
        put(bundle, "implementation.json", value)
    elif mutation == "selection":
        value = read(bundle, key + "/request.json")
        value["selected"].pop(next(iter(value["selected"])))
        put(bundle, key + "/request.json", value)
    elif mutation == "extra-ignore":
        put(bundle, "input/.semgrepignore", b"*.py\n")
    else:
        value = read(bundle, key + "/stdout.json")
        finding_file = next(file for file in value["files"] if file["findings"])
        finding = finding_file["findings"][0]
        if mutation == "catalog":
            value["rules"][0]["title"] = "Confirmed vulnerability"
        elif mutation == "request-binding":
            value["request_sha256"] = "0" * 64
        elif mutation == "suppression-policy":
            value["policy"] = "repository-policy"
        elif mutation == "drop-finding":
            finding_file["findings"].pop()
        elif mutation == "priority":
            finding["rule"]["severity"] = "low"
        elif mutation == "native-id":
            finding["record_id"] = "1" * 64
        elif mutation == "range":
            finding["location"]["end_line"] = 999999
        else:
            value["execution_state"] = "complete"
        put(bundle, key + "/stdout.json", value)
    seal(bundle)
    with pytest.raises(ValueError):
        load_custom_source(ROOT, bundle)


def reseal_derivative(root: Path) -> None:
    manifest = read(root, "report-manifest.json")
    for entry in manifest["entries"]:
        entry["sha256"] = sha256_file(root / entry["path"])
        entry["bytes"] = (root / entry["path"]).stat().st_size
    put(root, "report-manifest.json", manifest)


@pytest.mark.parametrize(
    "mutation",
    [
        "drop",
        "group",
        "inventory-as-finding",
        "hide-suppressed",
        "severity",
        "location",
        "pointer",
        "policy",
        "native-hash",
        "missing-run",
        "repeat-label",
    ],
)
def test_sarif_projection_not_just_counts(bundle: Path, tmp_path: Path, mutation: str) -> None:
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    sarif = read(output, "results.sarif")
    run = sarif["runs"][0]
    result = run["results"][0]
    if mutation == "drop":
        run["results"].pop()
    elif mutation == "group":
        run["results"] = run["results"][:1]
    elif mutation == "inventory-as-finding":
        run["results"].append(result.copy())
    elif mutation == "hide-suppressed":
        result["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
    elif mutation == "severity":
        result["level"] = "error"
    elif mutation == "location":
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = 1
        result["locations"][0]["physicalLocation"]["region"]["endLine"] = 999
    elif mutation == "pointer":
        result["properties"]["agentsecEvidence/nativePointer"] = "/files/999/findings/0"
    elif mutation == "policy":
        run["properties"]["agentsecEvidence/policy"] = "repository-policy"
    elif mutation == "native-hash":
        result["properties"]["agentsecEvidence/nativeReportSha256"] = "0" * 64
    elif mutation == "missing-run":
        sarif["runs"].pop()
    else:
        run["properties"]["agentsecEvidence/treatment"] = "all-repeat-2"
    put(output, "results.sarif", sarif)
    reseal_derivative(output)
    with pytest.raises(ValueError):
        validate_common_report(ROOT, output)


def test_overlap_not_merged_and_columns_not_misrepresented(bundle: Path) -> None:
    source, sarif = load_custom_source(ROOT, bundle)
    records = cast(list[dict[str, Any]], sarif["runs"])[0]["results"]
    assert len(records) == sum(
        len(file.findings or []) for file in source.summary.treatments[0].native.files
    )
    locations = [json.dumps(r["locations"], sort_keys=True) for r in records]
    assert len(set(locations)) < len(locations)
    for result in records:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert "startColumn" not in region and "snippet" not in region
        assert result["properties"]["agentsecEvidence/nativeUtf8ByteRange"]
        assert result["level"] == "warning"


def test_portable_derivative_validation_no_native_reopen(bundle: Path, tmp_path: Path) -> None:
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    relocated = tmp_path / "relocated"
    shutil.copytree(output, relocated)
    (bundle / "verification.json").write_bytes(b"invalidated source for this synthetic test")
    assert validate_common_report(ROOT, relocated)["passed"]
    with pytest.raises(ValueError):
        load_custom_source(ROOT, bundle)


def test_relocated_original_evidence_replays(bundle: Path, tmp_path: Path) -> None:
    relocated = tmp_path / "relocated"
    shutil.copytree(bundle, relocated)
    assert load_custom_source(ROOT, bundle) == load_custom_source(ROOT, relocated)


def test_duplicate_source_or_overwrite_refused(bundle: Path, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        write_common_report(project_root=ROOT, bundles=[bundle, bundle], output=tmp_path / "report")
    with pytest.raises(ValueError):
        write_common_report(project_root=ROOT, bundles=[bundle], output=bundle / "nested")
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    with pytest.raises(ValueError):
        write_common_report(project_root=ROOT, bundles=[bundle], output=output)


def test_unsupported_html_is_explicit(bundle: Path, tmp_path: Path) -> None:
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    with pytest.raises(ValueError, match="not yet supported"):
        read_presentation_inputs(ROOT, output)


def test_custom_repairs_are_not_silently_admitted_to_benchmark_scoring(bundle: Path) -> None:
    from agentsec_evidence.scoring.measurements import Context, source_rows

    context = Context(ROOT, "test-session", "test-case", "development", "test-attempt", 1, ())
    with pytest.raises(ValueError, match="not admitted"):
        source_rows(context, bundle)


def test_new_schema_does_not_replace_old() -> None:
    assert read(ROOT, "schemas/reporting-v5/common-report.schema.json") == (
        CustomCommonReport.model_json_schema()
    )
    assert (
        "common-report-v5"
        not in (ROOT / "schemas/reporting-v1/common-report.schema.json").read_text()
    )


def test_existing_cli_can_build_and_validate(bundle: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "cli"
    result = runner.invoke(app, ["report", "build", str(bundle), "--output", str(output)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["report", "validate", str(output)])
    assert result.exit_code == 0, result.output
    assert read(output, "report.json")["contract"] == "common-report-v5"


def test_exact_request_order_survives_sorted_derivative(bundle: Path, tmp_path: Path) -> None:
    raw = (bundle / "all-repeat-1/request.json").read_bytes()
    output = tmp_path / "report"
    report = write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    assert isinstance(report, CustomCommonReport)
    source = report.sources[0]
    assert source.kind == "custom-repair"
    row = source.summary.treatments[0]
    assert row.request_json.encode() == raw
    assert row.native.request_sha256 == sha256_bytes(raw)
    assert list(row.request.selected) != sorted(row.request.selected)
    assert parse_common_report((output / "report.json").read_bytes()) == report


@pytest.mark.parametrize("field", ["native_json", "request_json", "native", "request"])
def test_embedded_native_and_projection_must_agree(
    bundle: Path, tmp_path: Path, field: str
) -> None:
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    report = read(output, "report.json")
    row = report["sources"][0]["summary"]["treatments"][0]
    if field.endswith("_json"):
        row[field] += " "
    elif field == "native":
        row[field]["limitations"] = []
    else:
        row[field]["target_snapshot_id"] = "different"
    put(output, "report.json", report)
    reseal_derivative(output)
    with pytest.raises(ValueError):
        validate_common_report(ROOT, output)


def test_same_bundle_at_two_locations_not_independent_runs(bundle: Path, tmp_path: Path) -> None:
    other = tmp_path / "copy"
    shutil.copytree(bundle, other)
    with pytest.raises(ValueError, match="Duplicate source run"):
        write_common_report(project_root=ROOT, bundles=[bundle, other], output=tmp_path / "report")


def test_output_cannot_modify_an_unselected_sealed_repair(bundle: Path, tmp_path: Path) -> None:
    other = tmp_path / "unselected"
    shutil.copytree(bundle, other)
    with pytest.raises(ValueError, match="finalized evidence"):
        write_common_report(project_root=ROOT, bundles=[bundle], output=other / "nested")
    assert not (other / "nested").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_evidence_links_refused(bundle: Path, tmp_path: Path, kind: str) -> None:
    path = bundle / "all-repeat-1/stdout.json"
    outside = tmp_path / "native.json"
    shutil.copyfile(path, outside)
    path.unlink()
    try:
        if kind == "symlink":
            path.symlink_to(outside)
        else:
            path.hardlink_to(outside)
    except OSError:
        pytest.skip("Host does not permit link creation")
    with pytest.raises(ValueError):
        load_custom_source(ROOT, bundle)


def test_old_dependency_source_can_coexist_without_count_pooling(
    bundle: Path, tmp_path: Path
) -> None:
    from test_common_reporting import dependency_bundle

    dependency = dependency_bundle(tmp_path / "dependency")
    output = tmp_path / "mixed"
    report = write_common_report(project_root=ROOT, bundles=[bundle, dependency], output=output)
    assert isinstance(report, CustomCommonReport)
    assert {source.kind for source in report.sources} == {"dependency", "custom-repair"}
    assert report.sarif_runs == 6
    assert validate_common_report(ROOT, output)["passed"]
