from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Literal, cast

import typer
from pydantic import JsonValue
from rich.console import Console
from rich.table import Table

from agentsec_evidence import __version__
from agentsec_evidence.agents.records import AgentRunDetails
from agentsec_evidence.benchmarks.attempts import inspect_benchmark, retry_benchmark, run_benchmark
from agentsec_evidence.benchmarks.service import validate_plan
from agentsec_evidence.core.doctor import collect_doctor_report
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.mutations import Mutation
from agentsec_evidence.dependencies.pipeline import run_dependency_scan, validate_dependency_bundle
from agentsec_evidence.intake.snapshot import SnapshotError, create_snapshot
from agentsec_evidence.models.contracts import (
    BundleManifest,
    RunState,
    Summary,
    TargetSnapshot,
)
from agentsec_evidence.operations.offline import (
    load_existing_run,
    normalize_existing_run,
    rebuild_sarif,
    rebuild_summary,
    validate_existing_run,
)
from agentsec_evidence.orchestration.agent_pipeline import AgentScanRequest, run_agent_scan
from agentsec_evidence.orchestration.kics_pipeline import KicsScanRequest, run_kics_scan
from agentsec_evidence.orchestration.pipeline import SemgrepScanRequest, run_semgrep_scan
from agentsec_evidence.reporting.dependency import (
    load_dependency_run,
    resolve_dependency_run,
    summarize_dependency,
)
from agentsec_evidence.reporting.service import (
    load_report_source,
    require_new_derivative,
    validate_common_report,
    write_common_report,
)
from agentsec_evidence.research.retained import plain_path
from agentsec_evidence.reviews.service import validate_review, write_review

app = typer.Typer(
    name="agentsec-evidence",
    help="Orchestrate and preserve reproducible security evidence.",
    no_args_is_help=True,
    rich_markup_mode=None,
)
target_app = typer.Typer(help="Register and inspect immutable target snapshots.")
scan_app = typer.Typer(help="Run an approved scanner and finalize an evidence bundle.")
export_app = typer.Typer(help="Rebuild an interoperability export without rerunning a tool.")
dependency_app = typer.Typer(help="Run and validate the isolated dependency evidence experiment.")
report_app = typer.Typer(
    help="Build and validate common reports from existing evidence; no rescanning."
)
app.add_typer(report_app, name="report")
review_app = typer.Typer(
    help="Record contextual finding reviews without changing scanner evidence."
)
app.add_typer(review_app, name="review")
benchmark_app = typer.Typer(help="Validate and run explicitly admitted development benchmarks.")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(dependency_app, name="dependencies")
app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")
app.add_typer(export_app, name="export")
console = Console()

_SNAPSHOT_ID = re.compile(r"^snapshot_[0-9a-f]{64}$")


def _safe_text(value: object) -> str:
    return "".join(
        character if character >= " " and character != "\x7f" else "?" for character in str(value)
    )


def _emit_json(value: JsonValue) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _emit_error(exc: BaseException) -> None:
    typer.echo(f"error: {_safe_text(exc)}", err=True)


def _find_project_root(explicit: Path | None) -> Path:
    if explicit is not None:
        root = explicit.resolve(strict=True)
        if not (root / "pyproject.toml").is_file():
            raise ValueError("Project root does not contain pyproject.toml")
        return root
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file() and (
            candidate / "configs" / "tools" / "semgrep.toml"
        ).is_file():
            return candidate
    raise ValueError("Could not locate the agentsec-evidence development root")


def _workspace_root(project_root: Path, explicit: Path | None) -> Path:
    return (explicit or project_root / "workspace").resolve()


def _license_status(
    value: str,
) -> Literal["project-authored-private", "identified", "unknown"]:
    allowed = {"project-authored-private", "identified", "unknown"}
    if value not in allowed:
        raise ValueError(f"License status must be one of: {', '.join(sorted(allowed))}")
    return cast(Literal["project-authored-private", "identified", "unknown"], value)


def _source_kind(value: str) -> Literal["project-fixture", "local", "git"]:
    allowed = {"project-fixture", "local", "git"}
    if value not in allowed:
        raise ValueError(f"Source kind must be one of: {', '.join(sorted(allowed))}")
    return cast(Literal["project-fixture", "local", "git"], value)


def _terminal_exit_code(state: RunState) -> int:
    return {
        RunState.COMPLETE: 0,
        RunState.PARTIAL: 8,
        RunState.TIMED_OUT: 4,
        RunState.EXECUTION_FAILED: 4,
        RunState.PARSE_FAILED: 5,
        RunState.VALIDATION_FAILED: 5,
        RunState.REJECTED: 6,
        RunState.CANCELLED: 130,
    }.get(state, 5)


@app.command()
def version() -> None:
    """Print the installed application version."""
    typer.echo(__version__)


@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    strict: bool = typer.Option(False, help="Exit with code 3 when a requirement fails."),
) -> None:
    """Report prerequisites without changing the workspace."""
    report = collect_doctor_report()
    if json_output:
        _emit_json(cast(JsonValue, report.model_dump(mode="json")))
    else:
        table = Table(title="Environment")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        for check in report.checks:
            table.add_row(check.name, check.status, _safe_text(check.detail))
        console.print(table)

    if strict and not report.ready:
        raise typer.Exit(code=3)


@target_app.command("add")
def target_add(
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False, resolve_path=True)],
    label: Annotated[str, typer.Option("--label", help="Stable, non-secret source label.")],
    revision: Annotated[str, typer.Option(help="Commit, tag, or declared local revision.")],
    source_kind: Annotated[str, typer.Option(help="project-fixture, local, or git.")] = "local",
    license_status: Annotated[
        str,
        typer.Option(help="project-authored-private, identified, or unknown."),
    ] = "unknown",
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Create or resolve a deterministic target snapshot."""
    try:
        root = _find_project_root(project_root)
        result = create_snapshot(
            source,
            _workspace_root(root, workspace) / "targets",
            source_label=label,
            revision=revision,
            source_kind=_source_kind(source_kind),
            license_status=_license_status(license_status),
        )
    except (OSError, ValueError, SnapshotError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=6 if isinstance(exc, SnapshotError) else 2) from exc

    if json_output:
        _emit_json(cast(JsonValue, result.snapshot.model_dump(mode="json")))
        return
    table = Table(title="Target snapshot")
    table.add_column("Field")
    table.add_column("Value")
    for name, value in (
        ("snapshot", result.snapshot.snapshot_id),
        ("content sha256", result.snapshot.content_sha256),
        ("files", result.snapshot.file_count),
        ("bytes", result.snapshot.total_bytes),
        ("license", result.snapshot.license_status),
    ):
        table.add_row(name, _safe_text(value))
    console.print(table)


@target_app.command("inspect")
def target_inspect(
    snapshot_id: str,
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Read one registered snapshot without accepting a filesystem path."""
    try:
        if not _SNAPSHOT_ID.fullmatch(snapshot_id):
            raise ValueError("Invalid snapshot ID")
        root = _find_project_root(project_root)
        snapshot_path = _workspace_root(root, workspace) / "targets" / snapshot_id / "snapshot.json"
        snapshot = TargetSnapshot.model_validate_json(snapshot_path.read_bytes())
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=2) from exc
    if json_output:
        _emit_json(cast(JsonValue, snapshot.model_dump(mode="json")))
    else:
        console.print_json(data=snapshot.model_dump(mode="json"))


@scan_app.command("agent-audit")
def scan_agent_audit(
    case_id: Annotated[str, typer.Argument(help="Approved authored development case ID only.")],
    project_root: Annotated[Path | None, typer.Option()] = None,
    workspace: Annotated[Path | None, typer.Option()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate inputs in a bounded worker, then capture offline Agent Audit evidence."""
    try:
        root = _find_project_root(project_root)
        result = run_agent_scan(AgentScanRequest(root, _workspace_root(root, workspace), case_id))
        details = AgentRunDetails.model_validate_json(
            (result.run_root / "normalized/agent-details.json").read_bytes()
        )
    except (OSError, ValueError, SnapshotError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=2) from exc
    payload: JsonValue = {
        "run_id": result.run_id,
        "run_root": str(result.run_root),
        "terminal_state": result.terminal_state.value,
        "semantic_sha256": result.semantic_sha256,
        "summary": result.summary.model_dump(mode="json"),
        "agent_details": details.model_dump(mode="json"),
    }
    if json_output:
        _emit_json(payload)
    else:
        console.print_json(data=payload)
    raise typer.Exit(code=_terminal_exit_code(result.terminal_state))


@scan_app.command("semgrep")
def scan_semgrep(
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False, resolve_path=True)],
    label: Annotated[str, typer.Option("--label", help="Stable, non-secret source label.")],
    revision: Annotated[str, typer.Option(help="Commit, tag, or declared local revision.")],
    run_label: Annotated[
        str, typer.Option(help="Human-readable run label.")
    ] = "semgrep-first-slice",
    source_kind: Annotated[str, typer.Option(help="project-fixture, local, or git.")] = "local",
    license_status: Annotated[
        str,
        typer.Option(help="project-authored-private, identified, or unknown."),
    ] = "unknown",
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Run the pinned, isolated Semgrep first slice."""
    try:
        root = _find_project_root(project_root)
        result = run_semgrep_scan(
            SemgrepScanRequest(
                project_root=root,
                workspace_root=_workspace_root(root, workspace),
                target_source=source,
                source_label=label,
                revision=revision,
                run_label=run_label,
                source_kind=_source_kind(source_kind),
                license_status=_license_status(license_status),
            )
        )
    except SnapshotError as exc:
        _emit_error(exc)
        raise typer.Exit(code=6) from exc
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=2) from exc

    payload: JsonValue = {
        "run_id": result.run_id,
        "run_root": str(result.run_root),
        "semantic_sha256": result.semantic_sha256,
        "summary": result.summary.model_dump(mode="json"),
        "terminal_state": result.terminal_state.value,
    }
    if json_output:
        _emit_json(payload)
    else:
        table = Table(title="Semgrep evidence run")
        table.add_column("Field")
        table.add_column("Value")
        for name, value in (
            ("run", result.run_id),
            ("terminal state", result.terminal_state.value),
            ("findings", result.summary.normalized_finding_count),
            ("failures", result.summary.normalized_failure_count),
            ("SARIF valid", result.summary.sarif_valid),
            ("semantic sha256", result.semantic_sha256),
            ("bundle", result.run_root),
        ):
            table.add_row(name, _safe_text(value))
        console.print(table)
    exit_code = _terminal_exit_code(result.terminal_state)
    if exit_code:
        raise typer.Exit(code=exit_code)


@scan_app.command("kics")
def scan_kics(
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False, resolve_path=True)],
    label: Annotated[str, typer.Option("--label", help="Stable, non-secret source label.")],
    revision: Annotated[str, typer.Option(help="Commit, tag, or declared local revision.")],
    run_label: Annotated[
        str, typer.Option(help="Human-readable run label.")
    ] = "kics-g2-development",
    source_kind: Annotated[str, typer.Option(help="project-fixture, local, or git.")] = "local",
    license_status: Annotated[
        str,
        typer.Option(help="project-authored-private, identified, or unknown."),
    ] = "unknown",
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Run the pinned, isolated KICS G2 development adapter."""
    try:
        root = _find_project_root(project_root)
        result = run_kics_scan(
            KicsScanRequest(
                project_root=root,
                workspace_root=_workspace_root(root, workspace),
                target_source=source,
                source_label=label,
                revision=revision,
                run_label=run_label,
                source_kind=_source_kind(source_kind),
                license_status=_license_status(license_status),
            )
        )
    except SnapshotError as exc:
        _emit_error(exc)
        raise typer.Exit(code=6) from exc
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=2) from exc

    payload: JsonValue = {
        "run_id": result.run_id,
        "run_root": str(result.run_root),
        "semantic_sha256": result.semantic_sha256,
        "summary": result.summary.model_dump(mode="json"),
        "terminal_state": result.terminal_state.value,
    }
    if json_output:
        _emit_json(payload)
    else:
        table = Table(title="KICS evidence run")
        table.add_column("Field")
        table.add_column("Value")
        for name, value in (
            ("run", result.run_id),
            ("terminal state", result.terminal_state.value),
            ("findings", result.summary.normalized_finding_count),
            ("failures", result.summary.normalized_failure_count),
            ("SARIF valid", result.summary.sarif_valid),
            ("semantic sha256", result.semantic_sha256),
            ("bundle", result.run_root),
        ):
            table.add_row(name, _safe_text(value))
        console.print(table)
    exit_code = _terminal_exit_code(result.terminal_state)
    if exit_code:
        raise typer.Exit(code=exit_code)


@app.command("inspect")
def inspect_run(
    run_id: str,
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Inspect persisted run and summary records without executing a tool."""
    try:
        root = _find_project_root(project_root)
        if run_id.startswith("dep-run-"):
            dependency_root = resolve_dependency_run(_workspace_root(root, workspace), run_id)
            source, _ = load_report_source(root, dependency_root)
            _emit_json(source.model_dump(mode="json"))
            return
        existing = load_existing_run(_workspace_root(root, workspace), run_id)
        if existing.execution.producer.tool_id == "agent-audit":
            source, _ = load_report_source(root, existing.root)
            _emit_json(source.model_dump(mode="json"))
            return
        summary = Summary.model_validate_json(
            (existing.root / "exports" / "summary.json").read_bytes()
        )
        manifest = BundleManifest.model_validate_json(
            (existing.root / "bundle-manifest.json").read_bytes()
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=2) from exc
    payload: JsonValue = {
        "manifest_entries": len(manifest.entries),
        "run": existing.run.model_dump(mode="json"),
        "summary": summary.model_dump(mode="json"),
    }
    if json_output:
        _emit_json(payload)
    else:
        console.print_json(data=payload)


@app.command("validate")
def validate_run(
    run_id: str,
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Revalidate bundle hashes, schemas, provenance, and SARIF offline."""
    try:
        root = _find_project_root(project_root)
        if run_id.startswith("dep-run-"):
            dependency_root = resolve_dependency_run(_workspace_root(root, workspace), run_id)
            source, _ = load_report_source(root, dependency_root)
            _emit_json(
                {
                    "passed": True,
                    "run_id": run_id,
                    "state": source.state,
                    "dependency_bundle": "valid",
                    "reporting_sarif": "valid",
                }
            )
            return
        suite = validate_existing_run(
            project_root=root,
            workspace_root=_workspace_root(root, workspace),
            run_id=run_id,
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc
    payload: JsonValue = {
        "bundle": suite.bundle.model_dump(mode="json"),
        "passed": suite.passed,
        "provenance": suite.provenance.report.model_dump(mode="json"),
        "sarif": suite.sarif.model_dump(mode="json"),
        "schema": suite.schema.model_dump(mode="json"),
    }
    if json_output:
        _emit_json(payload)
    else:
        table = Table(title=f"Validation: {_safe_text(run_id)}")
        table.add_column("Layer")
        table.add_column("Status")
        for name, passed in (
            ("bundle", suite.bundle.passed),
            ("schema", suite.schema.passed),
            ("SARIF", suite.sarif.passed),
            ("provenance", suite.provenance.report.passed),
        ):
            table.add_row(name, "pass" if passed else "fail")
        console.print(table)
    if not suite.passed:
        raise typer.Exit(code=5)


@app.command("normalize")
def normalize_run(
    run_id: str,
    output: Annotated[Path, typer.Option(help="New derivative directory outside the run bundle.")],
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Reparse native evidence offline into a separate derivative directory."""
    try:
        root = _find_project_root(project_root)
        destination = normalize_existing_run(
            project_root=root,
            workspace_root=_workspace_root(root, workspace),
            run_id=run_id,
            output_root=output,
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc
    if json_output:
        _emit_json({"output": str(destination), "source_run_id": run_id})
    else:
        typer.echo(str(destination))


@export_app.command("sarif")
def export_sarif(
    run_id: str,
    output: Annotated[Path, typer.Option(help="New SARIF output path outside the run bundle.")],
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Rebuild and validate SARIF from normalized findings only."""
    try:
        root = _find_project_root(project_root)
        if run_id.startswith("dep-run-"):
            dependency_root = resolve_dependency_run(_workspace_root(root, workspace), run_id)
            _, document = load_report_source(root, dependency_root)
            destination = require_new_derivative(output, [dependency_root])
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(json_bytes(document))
            _emit_json(
                {
                    "output": str(destination),
                    "source_run_id": run_id,
                    "validation": {"passed": True},
                    "comparison_paths": ["osv-direct", "osv-sbom"],
                }
            )
            return
        report = rebuild_sarif(
            project_root=root,
            workspace_root=_workspace_root(root, workspace),
            run_id=run_id,
            output=output,
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc
    if json_output:
        _emit_json(
            {
                "output": str(output.resolve()),
                "source_run_id": run_id,
                "validation": report.model_dump(mode="json"),
            }
        )
    else:
        typer.echo(str(output.resolve()))


@app.command("summarize")
def summarize_run(
    run_id: str,
    project_root: Annotated[Path | None, typer.Option(help="Development repository root.")] = None,
    workspace: Annotated[
        Path | None, typer.Option(help="Authoritative private workspace root.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Summarize static or dependency evidence without rerunning any producer."""
    try:
        root = _find_project_root(project_root)
        if run_id.startswith("dep-run-"):
            existing_dependency = load_dependency_run(
                resolve_dependency_run(_workspace_root(root, workspace), run_id)
            )
            _emit_json(summarize_dependency(existing_dependency).model_dump(mode="json"))
            return
        summary = rebuild_summary(
            project_root=root,
            workspace_root=_workspace_root(root, workspace),
            run_id=run_id,
        )
        existing = load_existing_run(_workspace_root(root, workspace), run_id)
        if existing.execution.producer.tool_id == "agent-audit":
            source, _ = load_report_source(root, existing.root)
            _emit_json(source.model_dump(mode="json"))
            return
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc
    if json_output:
        _emit_json(cast(JsonValue, summary.model_dump(mode="json")))
    else:
        console.print_json(data=summary.model_dump(mode="json"))


@dependency_app.command("run")
def dependency_run(
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    database: Annotated[Path, typer.Option(help="Frozen PyPI all.zip; never downloaded here.")],
    database_sha256: Annotated[str, typer.Option(help="Expected SHA-256 of the frozen archive.")],
    label: Annotated[str, typer.Option(help="Non-secret target identity.")],
    revision: Annotated[str, typer.Option(help="Fixed revision or authored fixture version.")],
    split: Annotated[
        str, typer.Option(help="development or pilot; pilot needs admission.")
    ] = "development",
    admission: Annotated[Path | None, typer.Option(help="Reviewed pilot admission record.")] = None,
    mutation: Annotated[
        str | None, typer.Option(help="Development-only controlled SBOM change.")
    ] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    workspace: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Compare direct lockfile and SBOM-mediated offline matching; emit JSON."""
    try:
        if split not in {"development", "pilot"}:
            raise ValueError("Only development and reviewed pilot splits are supported")
        if mutation not in {None, "remove-component", "remove-purl", "change-version"}:
            raise ValueError("Unsupported development mutation")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", database_sha256):
            raise ValueError("Database hash must be SHA-256")
        root = _find_project_root(project_root)
        result = run_dependency_scan(
            project_root=root,
            workspace_root=_workspace_root(root, workspace),
            source=source,
            label=label,
            revision=revision,
            database=database,
            database_sha256=database_sha256.lower(),
            split=cast(Literal["development", "pilot"], split),
            admission_file=admission,
            mutation=cast(Mutation | None, mutation),
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=2) from exc
    _emit_json(result)
    if result["state"] != "complete":
        raise typer.Exit(code=8 if result["state"] == "partial" else 4)


@dependency_app.command("validate")
def dependency_validate(
    bundle: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
) -> None:
    """Check the separate dependency bundle format offline."""
    try:
        _emit_json(validate_dependency_bundle(bundle))
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@report_app.command("build")
def report_build(
    bundles: Annotated[list[Path], typer.Argument(exists=True, file_okay=False)],
    output: Annotated[
        Path, typer.Option(help="New derivative directory outside finalized evidence.")
    ],
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Combine validated source views without collapsing sources, targets or comparison paths."""
    try:
        report = write_common_report(
            project_root=_find_project_root(project_root), bundles=bundles, output=output
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc
    _emit_json(
        {
            "output": str(output.resolve()),
            "sources": len(report.sources),
            "sarif_runs": report.sarif_runs,
            "sensitivity": report.sensitivity,
        }
    )


@report_app.command("validate")
def report_validate(
    directory: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Validate report integrity, source bindings and SARIF/result accounting offline."""
    try:
        _emit_json(validate_common_report(_find_project_root(project_root), directory))
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@review_app.command("build")
def review_build(
    report: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    batch: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option(help="New review revision directory; never overwritten.")],
    previous: Annotated[
        Path | None, typer.Option(exists=True, file_okay=False, help="Prior review revision.")
    ] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Append a supplied annotation batch; declared reviewers are not authenticated."""
    try:
        sidecar = write_review(
            project=_find_project_root(project_root),
            report_root=report,
            batch_path=batch,
            output=output,
            previous=previous,
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc
    _emit_json(
        {
            "output": str(output.resolve()),
            "annotation_count": len(sidecar.annotations),
            "report_manifest_sha256": sidecar.report_manifest_sha256,
            "identity_assurance": sidecar.reviewer_identity_assurance,
        }
    )


@review_app.command("validate")
def review_validate(
    directory: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    report: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    previous: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Check report binding and annotation history; optionally verify the previous revision."""
    try:
        _emit_json(
            validate_review(
                project=_find_project_root(project_root),
                report_root=report,
                root=directory,
                previous=previous,
            )
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@benchmark_app.command("validate")
def benchmark_validate(
    plan: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Check the admitted development plan's scope, expectations and exact byte pins."""
    try:
        if project_root is not None:
            plain_path(project_root, directory=True)
        result = validate_plan(_find_project_root(project_root), plan)
        _emit_json(
            {
                "plan_valid": result.plan_valid,
                "plan_id": result.plan_id,
                "plan_sha256": result.plan_sha256,
                "plan_semantic_sha256": result.plan_semantic_sha256,
                "planned_cells": len(result.cells),
                "execution_authorized": result.execution_authorized,
                "runtime_readiness": result.runtime_readiness,
                "validation_scope": result.validation_scope,
            }
        )
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@benchmark_app.command("dry-run")
def benchmark_dry_run(
    plan: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """List ordered cells and unresolved readiness without Docker, target parsing or scans."""
    try:
        if project_root is not None:
            plain_path(project_root, directory=True)
        result = validate_plan(_find_project_root(project_root), plan)
        _emit_json(cast(JsonValue, result.model_dump(mode="json")))
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@benchmark_app.command("status")
def benchmark_status(
    plan: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Revalidate retained attempts without launching scanners or retrying failures."""
    try:
        if project_root is not None:
            plain_path(project_root, directory=True)
        result = inspect_benchmark(_find_project_root(project_root), plan)
        _emit_json(cast(JsonValue, result.model_dump(mode="json")))
        if result.blocked:
            raise typer.Exit(code=5)
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@benchmark_app.command("run")
def benchmark_run(
    plan: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    project_root: Annotated[Path | None, typer.Option()] = None,
    max_new_cells: Annotated[int, typer.Option(min=1, max=39)] = 39,
) -> None:
    """Run/resume the frozen authored treatment serially; no retries or target execution."""
    try:
        if project_root is not None:
            plain_path(project_root, directory=True)
        result = run_benchmark(_find_project_root(project_root), plan, max_new_cells=max_new_cells)
        _emit_json(cast(JsonValue, result.model_dump(mode="json")))
        if result.blocked:
            raise typer.Exit(code=5)
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


@benchmark_app.command("retry")
def benchmark_retry(
    plan: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    attempt_id: Annotated[str, typer.Option()],
    cause: Annotated[str, typer.Option()],
    remediation: Annotated[str, typer.Option()],
    project_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Explicitly retry one plan-authorized missing-Docker failure; preserve both attempts."""
    try:
        if project_root is not None:
            plain_path(project_root, directory=True)
        result = retry_benchmark(
            _find_project_root(project_root),
            plan,
            attempt_id=attempt_id,
            cause=cause,
            remediation=remediation,
        )
        _emit_json(cast(JsonValue, result.model_dump(mode="json")))
        if result.blocked:
            raise typer.Exit(code=5)
    except (OSError, ValueError) as exc:
        _emit_error(exc)
        raise typer.Exit(code=5) from exc


def main() -> None:
    app()
