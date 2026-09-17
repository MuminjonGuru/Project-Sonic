from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import JsonValue

from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.models.contracts import ExecutionOutcome, ExecutionRecord, Sensitivity
from agentsec_evidence.orchestration import kics_pipeline, pipeline, shared
from agentsec_evidence.storage.bundle import RunBundle


@dataclass(frozen=True)
class ExampleProducer:
    tool_id: str = "example-producer"
    tool_version: str = "1.0.0"
    adapter_id: str = "example-json"
    adapter_version: str = "0.1.0"
    image: str = "example@sha256:" + "a" * 64


@pytest.fixture
def prepared(tmp_path: Path) -> shared.PreparedWorkspace:
    target = tmp_path / "target"
    target.mkdir()
    (target / "input.txt").write_bytes(b"project-authored fixture\n")
    return shared.prepare_workspace(
        workspace_root=tmp_path / "workspace",
        target_source=target,
        source_label="fixture:shared-orchestration",
        revision="fixture-v1",
        source_kind="project-fixture",
        license_status="project-authored-private",
    )


@pytest.fixture
def execution(prepared: shared.PreparedWorkspace) -> ExecutionRecord:
    project_root = Path(__file__).resolve().parents[2]
    profile = load_toml_config(
        project_root / "configs" / "profiles" / "development.toml", ExecutionProfile
    ).value
    return shared.make_execution(
        execution_id="execution_example",
        run_id="run_example",
        snapshot=prepared.snapshot_result.snapshot,
        tool=ExampleProducer(),
        profile=profile,
        config_sha256="b" * 64,
        ruleset_sha256="c" * 64,
        portable_argv=["docker", "run"],
        environment=prepared.environment,
        capture=None,
        outcome=ExecutionOutcome.FAILED,
        native_byte_length=0,
        cleanup_attempted=False,
        cleanup_succeeded=None,
    )


def test_shared_module_does_not_import_producers() -> None:
    assert shared.__file__ is not None
    tree = ast.parse(Path(shared.__file__).read_text(encoding="utf-8"))
    forbidden = (
        "agentsec_evidence.adapters",
        "agentsec_evidence.orchestration.pipeline",
        "agentsec_evidence.orchestration.kics_pipeline",
    )
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    assert not any(name.startswith(forbidden) for name in imports)
    for module in (pipeline, kics_pipeline):
        assert module.prepare_workspace is shared.prepare_workspace
        assert module.store_blob is shared.store_blob
        assert module.finish_run is shared.finish_run
        assert module.make_execution is shared.make_execution


def test_kics_has_no_import_from_semgrep_pipeline() -> None:
    assert kics_pipeline.__file__ is not None
    tree = ast.parse(Path(kics_pipeline.__file__).read_text(encoding="utf-8"))
    assert all(
        not isinstance(node, ast.ImportFrom)
        or node.module != "agentsec_evidence.orchestration.pipeline"
        for node in ast.walk(tree)
    )


def test_pipeline_result_compatibility_import() -> None:
    assert pipeline.PipelineResult is shared.PipelineResult
    assert kics_pipeline.PipelineResult is shared.PipelineResult


def test_metadata_accepts_a_structural_producer(execution: ExecutionRecord) -> None:
    assert execution.producer.tool_id == "example-producer"
    assert execution.image == ExampleProducer().image
    assert execution.exit_code is None
    assert execution.outcome is ExecutionOutcome.FAILED


def test_environment_does_not_inherit_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "NOT_A_REAL_SECRET_shared_orchestration_82"
    for key in ("OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "HTTP_PROXY", "DOCKER_HOST"):
        monkeypatch.setenv(key, canary)
    environment = shared.minimal_environment(tmp_path / "runtime")
    assert canary not in environment.values()
    assert set(environment) <= {
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "DOCKER_CLI_HINTS",
        "DOCKER_CONFIG",
        "HOME",
        "TEMP",
        "TMP",
        "USERPROFILE",
    }
    assert Path(environment["HOME"]).is_dir()
    assert Path(environment["DOCKER_CONFIG"]).is_dir()


def test_preparation_snapshots_without_executing_target(
    prepared: shared.PreparedWorkspace, tmp_path: Path
) -> None:
    snapshot = prepared.snapshot_result
    assert snapshot.snapshot.file_count == 1
    assert (snapshot.content_root / "input.txt").read_bytes() == b"project-authored fixture\n"
    assert (tmp_path / "target" / "input.txt").read_bytes() == b"project-authored fixture\n"
    assert snapshot.content_root != tmp_path / "target"


def test_capture_preserves_exact_bytes(prepared: shared.PreparedWorkspace, tmp_path: Path) -> None:
    raw = b"\x00\xff\r\nexact producer bytes\n"
    with RunBundle.create(
        tmp_path / "workspace",
        run_label="capture-test",
        profile_id="development-static-v1",
        config_sha256="b" * 64,
        snapshot_result=prepared.snapshot_result,
    ) as bundle:
        descriptor = shared.store_blob(
            bundle=bundle,
            blob_store=prepared.blob_store,
            relative_path="executions/example/native/report.bin",
            data=raw,
            media_type="application/octet-stream",
            sensitivity=Sensitivity.INTERNAL,
            producer="example-producer",
            logical_role="native-report",
        )
        assert descriptor.sha256 == sha256_bytes(raw)
        assert sha256_file(bundle.root / descriptor.relative_path) == descriptor.sha256
        assert descriptor.byte_length == len(raw)


def test_failure_and_coverage_require_producer_specific_scope(
    prepared: shared.PreparedWorkspace, execution: ExecutionRecord
) -> None:
    failure = shared.failure_record(
        run_id=execution.run_id,
        execution_id=execution.execution_id,
        stage="launch",
        category="missing-tool",
        message="Failed\x1b\nlaunch",
        evidence=[],
        affected_scope="example-producer execution",
    )
    coverage = shared.build_failed_coverage(
        run_id=execution.run_id,
        execution_id=execution.execution_id,
        snapshot=prepared.snapshot_result.snapshot,
        producer=execution.producer,
        execution="failed",
        property_id="example.analysis",
    )
    assert failure.affected_scope == "example-producer execution"
    assert failure.sanitized_message == "Failed??launch"
    assert coverage.property_id == "example.analysis"
    assert coverage.observation == "unknown"


def test_semantic_projection_ignores_ids_but_detects_substantive_changes(
    prepared: shared.PreparedWorkspace, execution: ExecutionRecord
) -> None:
    def digest(record: ExecutionRecord, sarif: dict[str, JsonValue]) -> str:
        return semantic_hash(
            shared.build_semantic_document(
                snapshot=prepared.snapshot_result.snapshot,
                execution=record,
                parser_report=None,
                findings=[],
                coverage=[],
                failures=[],
                sarif=sarif,
            )
        )

    original = digest(execution, {"version": "2.1.0", "runs": []})
    volatile = execution.model_copy(update={"execution_id": "execution_other", "duration_ns": 99})
    assert digest(volatile, {"version": "2.1.0", "runs": []}) == original
    substantive = execution.model_copy(update={"exit_code": 127})
    assert digest(substantive, {"version": "2.1.0", "runs": []}) != original
    assert digest(execution, {"version": "2.1.0", "runs": [{"results": [{}]}]}) != original


def test_staging_cleanup_refuses_paths_outside_its_root(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(RuntimeError, match="outside the staging root"):
        shared.remove_staging(staging, outside)
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
