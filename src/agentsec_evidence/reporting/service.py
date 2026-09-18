from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.models.contracts import Summary
from agentsec_evidence.operations.offline import load_existing_run, validate_existing_run
from agentsec_evidence.reporting.dependency import (
    dependency_sarif,
    load_dependency_run,
    summarize_dependency,
)
from agentsec_evidence.reporting.models import (
    CommonReport,
    DependencySource,
    ReportSource,
    StaticSource,
)
from agentsec_evidence.validation.checks import validate_sarif


def require_new_derivative(path: Path, sources: list[Path]) -> Path:
    destination = path.resolve()
    if destination.exists() or any(destination.is_relative_to(root.resolve()) for root in sources):
        raise ValueError("Derived output must be new and outside source bundles")
    for parent in destination.parents:
        if (parent / "bundle-manifest.json").is_file() or (
            (parent / "manifest.json").is_file() and (parent / "report.json").is_file()
        ):
            raise ValueError("Derived output cannot modify any finalized evidence bundle")
    return destination


def validate_report_sarif(project_root: Path, document: dict[str, JsonValue]) -> None:
    runs = document.get("runs")
    if document.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
        raise ValueError("A common SARIF log requires explicit runs")
    for index, run in enumerate(runs):
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise ValueError("Missing SARIF result accounting")
        report = validate_sarif(
            run_id=f"report-run-{index}",
            document={**document, "runs": [run]},
            schema_path=project_root / "schemas/vendor/oasis/sarif-schema-2.1.0.json",
            expected_results=len(cast(list[JsonValue], run["results"])),
        )
        if not report.passed:
            raise ValueError(
                "Common SARIF validation failed: "
                + "; ".join(item.detail for item in report.checks if not item.passed)
            )


def load_report_source(
    project_root: Path, bundle: Path
) -> tuple[ReportSource, dict[str, JsonValue]]:
    root = bundle.resolve(strict=True)
    if (root / "manifest.json").is_file():
        existing = load_dependency_run(root)
        summary = summarize_dependency(existing)
        source: ReportSource = DependencySource(
            run_id=summary.run_id,
            state=summary.state,
            label=str(existing.report.get("label", "unknown")),
            revision=str(existing.report.get("revision", "unknown")),
            target_content_sha256=cast(str | None, existing.report.get("snapshot_sha256")),
            source_semantic_sha256=cast(str | None, existing.report.get("semantic_sha256")),
            source_manifest_sha256=sha256_file(root / "manifest.json"),
            summary=summary,
        )
        document = dependency_sarif(existing)
    else:
        if root.parent.name != "runs":
            raise ValueError("Static source must be a finalized workspace/runs bundle")
        workspace = root.parent.parent
        suite = validate_existing_run(
            project_root=project_root, workspace_root=workspace, run_id=root.name
        )
        if not suite.passed:
            raise ValueError("Static source did not pass integrity/schema/provenance checks")
        static = load_existing_run(workspace, root.name)
        source = StaticSource(
            run_id=static.run.run_id,
            state=static.run.terminal_state.value if static.run.terminal_state else "unknown",
            label=static.target.source_label,
            revision=static.target.revision,
            target_content_sha256=static.target.content_sha256,
            source_semantic_sha256=static.run.semantic_sha256,
            source_manifest_sha256=sha256_file(root / "bundle-manifest.json"),
            summary=Summary.model_validate_json((root / "exports/summary.json").read_bytes()),
            coverage=list(static.coverage),
            failures=list(static.failures),
        )
        document = cast(
            dict[str, JsonValue], json.loads((root / "exports/results.sarif").read_bytes())
        )
        for run in cast(list[dict[str, JsonValue]], document["runs"]):
            properties = cast(dict[str, JsonValue], run.setdefault("properties", {}))
            properties.update(
                {
                    "agentsecEvidence/sourceRunId": source.run_id,
                    "agentsecEvidence/sourceManifestSha256": source.source_manifest_sha256,
                }
            )
    validate_report_sarif(project_root, document)
    return source, document


def write_common_report(*, project_root: Path, bundles: list[Path], output: Path) -> CommonReport:
    if not bundles:
        raise ValueError("At least one evidence bundle is required")
    roots = [path.resolve(strict=True) for path in bundles]
    if len(set(roots)) != len(roots):
        raise ValueError("Duplicate source bundle")
    destination = require_new_derivative(output, roots)
    sources: list[ReportSource] = []
    runs: list[JsonValue] = []
    for root in sorted(roots, key=lambda path: path.name):
        source, document = load_report_source(project_root, root)
        if any(item.run_id == source.run_id for item in sources):
            raise ValueError("Duplicate source run identity")
        sources.append(source)
        runs.extend(cast(list[JsonValue], document["runs"]))
    document = {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": runs}
    validate_report_sarif(project_root, document)
    report = CommonReport(
        generated_at=utc_now(),
        sources=sources,
        sarif_runs=len(runs),
        provenance={
            "reporter_sources": [
                {"path": path.relative_to(project_root).as_posix(), "sha256": sha256_file(path)}
                for path in sorted((project_root / "src/agentsec_evidence/reporting").glob("*.py"))
            ]
        },
    )
    destination.mkdir(parents=True, exist_ok=False)
    files = {
        "report.json": json_bytes(report.model_dump(mode="json")),
        "results.sarif": json_bytes(document),
    }
    for name, data in files.items():
        with (destination / name).open("xb") as handle:
            handle.write(data)
    manifest: JsonValue = {
        "contract": "common-report-manifest-v1",
        "source_manifests": [
            {"run_id": source.run_id, "sha256": source.source_manifest_sha256} for source in sources
        ],
        "entries": [
            {"path": name, "sha256": sha256_file(destination / name), "bytes": len(data)}
            for name, data in files.items()
        ],
    }
    with (destination / "report-manifest.json").open("xb") as handle:
        handle.write(json_bytes(manifest))
    validate_common_report(project_root, destination)
    return report


def validate_common_report(project_root: Path, root: Path) -> dict[str, JsonValue]:
    root = root.resolve(strict=True)
    try:
        if (root / "report-manifest.json").is_symlink():
            raise ValueError("Common report manifest cannot be a symbolic link")
        manifest = json.loads((root / "report-manifest.json").read_bytes())
        if manifest["contract"] != "common-report-manifest-v1":
            raise ValueError("Unsupported common report manifest")
        expected = {"report.json", "results.sarif"}
        entries = manifest["entries"]
        if len(entries) != 2 or {entry["path"] for entry in entries} != expected:
            raise ValueError("Unexpected common report entries")
        if {path.name for path in root.iterdir()} != expected | {"report-manifest.json"}:
            raise ValueError("Unmanifested common report content")
        for entry in entries:
            path = root / entry["path"]
            if (
                path.is_symlink()
                or path.stat().st_size != entry["bytes"]
                or sha256_file(path) != entry["sha256"]
            ):
                raise ValueError("Common report integrity failure")
        report = CommonReport.model_validate_json((root / "report.json").read_bytes())
        source_refs = [
            {"run_id": source.run_id, "sha256": source.source_manifest_sha256}
            for source in report.sources
        ]
        if manifest["source_manifests"] != source_refs or len(
            {source.run_id for source in report.sources}
        ) != len(report.sources):
            raise ValueError("Common report source binding failure")
        document = cast(dict[str, JsonValue], json.loads((root / "results.sarif").read_bytes()))
        validate_report_sarif(project_root, document)
        runs = cast(list[dict[str, JsonValue]], document["runs"])
        if len(runs) != report.sarif_runs:
            raise ValueError("Common report SARIF run accounting failure")
        expected_runs = sum(2 if source.kind == "dependency" else 1 for source in report.sources)
        if len(runs) != expected_runs:
            raise ValueError("Missing or additional SARIF source run")
        for source in report.sources:
            matching = [
                run
                for run in runs
                if cast(dict[str, JsonValue], run.get("properties", {})).get(
                    "agentsecEvidence/sourceRunId"
                )
                == source.run_id
            ]
            if len(matching) != (2 if source.kind == "dependency" else 1):
                raise ValueError("SARIF source linkage is incomplete")
            for run in matching:
                properties = cast(dict[str, JsonValue], run["properties"])
                if (
                    properties.get("agentsecEvidence/sourceManifestSha256")
                    != source.source_manifest_sha256
                ):
                    raise ValueError("SARIF source manifest linkage differs")
            if isinstance(source, DependencySource):
                paths = [
                    cast(dict[str, JsonValue], run["properties"]).get(
                        "agentsecEvidence/comparisonPath"
                    )
                    for run in matching
                ]
                if set(paths) != {"osv-direct", "osv-sbom"}:
                    raise ValueError("Dependency comparison paths must remain separate")
                for run, path in zip(matching, paths, strict=True):
                    row = next(item for item in source.summary.stages if item.stage == path)
                    if len(cast(list[JsonValue], run["results"])) != (
                        row.reported_match_occurrences or 0
                    ):
                        raise ValueError("Dependency result accounting differs from summary")
            elif (
                len(cast(list[JsonValue], matching[0]["results"]))
                != source.summary.normalized_finding_count
            ):
                raise ValueError("Static result accounting differs from summary")
    except (KeyError, TypeError, AttributeError, StopIteration) as exc:
        raise ValueError("Malformed common reporting structure") from exc
    return {
        "passed": True,
        "contract": "common-report-v1",
        "sources": len(report.sources),
        "sarif_runs": len(runs),
    }
