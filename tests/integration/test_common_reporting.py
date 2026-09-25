from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue
from typer.testing import CliRunner

from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.analysis import SEMANTIC_VERSION, dependency_semantic_hash
from agentsec_evidence.dependencies.models import StageEvidence
from agentsec_evidence.dependencies.parsers import (
    parse_cyclonedx,
    parse_lockfile,
    parse_osv,
    parse_syft,
)
from agentsec_evidence.dependencies.pipeline import seal_bundle
from agentsec_evidence.reporting.dependency import (
    dependency_sarif,
    load_dependency_run,
    summarize_dependency,
)
from agentsec_evidence.reporting.models import CommonReport, DependencySummary
from agentsec_evidence.reporting.service import validate_common_report, write_common_report

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "model,name", [(CommonReport, "common-report"), (DependencySummary, "dependency-summary")]
)
def test_committed_reporting_schemas_match_models(
    model: type[CommonReport] | type[DependencySummary], name: str
) -> None:
    stored = json.loads((ROOT / f"schemas/reporting-v1/{name}.schema.json").read_bytes())
    assert stored == model.model_json_schema()


def _put(root: Path, name: str, value: JsonValue | bytes) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else json_bytes(value))


def dependency_bundle(tmp_path: Path, *, findings: bool = True, state: str = "complete") -> Path:
    root = tmp_path / "workspace/dependency-runs" / ("dep-run-" + "a" * 32)
    root.mkdir(parents=True)
    report: dict[str, JsonValue] = {
        "contract": "dependency-run-v1",
        "run_id": root.name,
        "label": "synthetic:test",
        "revision": "test-v1",
        "state": state,
        "stages": {
            path: {"exit_code": 1 if findings else 0} for path in ("osv-direct", "osv-sbom")
        },
    }
    if state != "failed":
        data = (ROOT / "test_cases/development/dependency-basic/target/uv.lock").read_bytes()
        lock, scope = parse_lockfile(data)
        _put(root, "inputs/uv.lock", data)
        _put(root, "scope.json", scope.model_dump(mode="json"))
        components: list[JsonValue] = [
            {
                "name": item.name,
                "version": item.version,
                "type": "library",
                "bom-ref": str(index),
                "purl": f"pkg:pypi/{item.name}@{item.version}",
            }
            for index, item in enumerate(lock.observations)
        ]
        syft_data = json_bytes(
            {
                "schema": {"version": "16.1.10"},
                "artifacts": [
                    {**cast(dict[str, JsonValue], item), "id": str(index), "type": "python"}
                    for index, item in enumerate(components)
                ],
            }
        )
        cdx_data = json_bytes(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
        )
        osv_data = json_bytes(
            {
                "results": [
                    {
                        "source": {"path": "/src/uv.lock"},
                        "packages": [
                            {
                                "package": {
                                    "name": item.name,
                                    "version": item.version,
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [{"id": "GHSA-test"}]
                                if findings and item.name == "requests" and item.version == "2.31.0"
                                else [],
                            }
                            for item in lock.observations
                        ],
                    }
                ]
            }
        )
        stages: list[StageEvidence] = [lock, parse_syft(syft_data), parse_cyclonedx(cdx_data)]
        _put(root, "native/syft/syft.json", syft_data)
        _put(root, "native/syft/bom.cdx.json", cdx_data)
        for path in ("osv-direct", "osv-sbom"):
            if state == "partial" and path == "osv-sbom":
                continue
            _put(root, f"native/{path}/osv.json", osv_data)
            stages.append(
                parse_osv(
                    osv_data,
                    stage_name=path,
                    exit_code=1 if findings else 0,
                    alias_groups={"GHSA-test": ("CVE-TEST", "GHSA-test")},
                )
            )
        for stage in stages:
            _put(root, f"normalized/{stage.stage}.json", stage.model_dump(mode="json"))
        _put(
            root, "configuration/tools.json", (ROOT / "configs/dependency/tools.json").read_bytes()
        )
        report.update(
            {
                "semantic_version": SEMANTIC_VERSION,
                "semantic_sha256": dependency_semantic_hash(stages, scope),
                "snapshot_sha256": "1" * 64,
                "database_sha256": "2" * 64,
            }
        )
    _put(root, "report.json", report)
    seal_bundle(root)
    return root


@pytest.mark.parametrize("findings", [False, True])
def test_dependency_summary_and_sarif_keep_paths_identity_and_evidence(
    tmp_path: Path, findings: bool
) -> None:
    bundle = dependency_bundle(tmp_path, findings=findings)
    before = {
        str(path.relative_to(bundle)): sha256_file(path)
        for path in bundle.rglob("*")
        if path.is_file()
    }
    output = tmp_path / "derived"
    report = write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    assert report.sources[0].summary.contract == "dependency-summary-v1"  # type: ignore[union-attr]
    assert report.sarif_runs == 2
    assert validate_common_report(ROOT, output)["passed"]
    document = json.loads((output / "results.sarif").read_bytes())
    for run in document["runs"]:
        assert len(run["results"]) == int(findings)
        assert run["invocations"][0]["executionSuccessful"] is True
        if findings:
            result = run["results"][0]
            assert result["ruleId"] == "CVE-TEST" and result["level"] == "none"
            assert result["properties"]["agentsecEvidence/aliases"] == ["CVE-TEST", "GHSA-test"]
            assert "physicalLocation" not in result["locations"][0]
            assert result["properties"]["agentsecEvidence/jsonPointer"].startswith("/results/")
    after = {
        str(path.relative_to(bundle)): sha256_file(path)
        for path in bundle.rglob("*")
        if path.is_file()
    }
    assert before == after
    second = tmp_path / "second"
    write_common_report(project_root=ROOT, bundles=[bundle], output=second)
    assert (output / "results.sarif").read_bytes() == (second / "results.sarif").read_bytes()


@pytest.mark.parametrize("state", ["partial", "failed"])
def test_missing_stages_are_null_and_failed_invocations_not_clean(
    tmp_path: Path, state: str
) -> None:
    bundle = dependency_bundle(tmp_path, state=state)
    existing = load_dependency_run(bundle)
    summary = summarize_dependency(existing)
    missing = next(item for item in summary.stages if item.stage == "osv-sbom")
    assert missing.state == "missing" and missing.reported_match_occurrences is None
    if state == "failed":
        assert summary.eligible_unique_packages is None and not summary.scope_available
    document = dependency_sarif(existing)
    runs = cast(list[dict[str, JsonValue]], document["runs"])
    invocation = cast(list[dict[str, JsonValue]], runs[1]["invocations"])[0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"]
    write_common_report(project_root=ROOT, bundles=[bundle], output=tmp_path / "derived")


def test_common_report_refuses_corruption_duplicate_inputs_and_overwrites(tmp_path: Path) -> None:
    bundle = dependency_bundle(tmp_path)
    with pytest.raises(ValueError, match="Duplicate"):
        write_common_report(
            project_root=ROOT, bundles=[bundle, bundle], output=tmp_path / "duplicate"
        )
    with pytest.raises(ValueError, match="outside"):
        write_common_report(project_root=ROOT, bundles=[bundle], output=bundle / "bad")
    output = tmp_path / "derived"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    with pytest.raises(ValueError):
        write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    (output / "results.sarif").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        validate_common_report(ROOT, output)
    (bundle / "native/osv-direct/osv.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        write_common_report(project_root=ROOT, bundles=[bundle], output=tmp_path / "corrupt")
    assert not (tmp_path / "corrupt").exists()


def test_dependency_cli_uses_common_commands_without_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = dependency_bundle(tmp_path)
    import agentsec_evidence.dependencies.pipeline as pipeline

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Reporting must not invoke any producer")

    monkeypatch.setattr(pipeline, "run_bounded_process", forbidden)
    runner = CliRunner()
    common = ["--project-root", str(ROOT), "--workspace", str(bundle.parent.parent)]
    for command in ("inspect", "summarize", "validate"):
        result = runner.invoke(app, [command, bundle.name, *common, "--json"])
        assert result.exit_code == 0, result.output
        json.loads(result.stdout)
    export = tmp_path / "export.sarif"
    result = runner.invoke(
        app, ["export", "sarif", bundle.name, *common, "--output", str(export), "--json"]
    )
    assert result.exit_code == 0, result.output
    output = tmp_path / "report"
    built = runner.invoke(
        app, ["report", "build", str(bundle), "--output", str(output), "--project-root", str(ROOT)]
    )
    assert built.exit_code == 0, built.output
    validated = runner.invoke(app, ["report", "validate", str(output), "--project-root", str(ROOT)])
    assert validated.exit_code == 0, validated.output
    assert json.loads(validated.stdout)["sarif_runs"] == 2


def test_sealed_partial_bundle_cannot_claim_complete(tmp_path: Path) -> None:
    bundle = dependency_bundle(tmp_path, state="partial")
    (bundle / "manifest.json").unlink()
    report = json.loads((bundle / "report.json").read_bytes())
    report["state"] = "complete"
    _put(bundle, "report.json", report)
    seal_bundle(bundle)
    with pytest.raises(ValueError, match="complete stage"):
        load_dependency_run(bundle)
