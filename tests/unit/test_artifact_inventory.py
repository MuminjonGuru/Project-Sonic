from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue, ValidationError

from agentsec_evidence.agents.artifact_catalog import RECOGNIZERS, match_path
from agentsec_evidence.agents.inventory import (
    MAX_INVENTORY_FILES,
    ArtifactInventory,
    artifact_inventory_semantic_sha256,
    build_artifact_inventory,
)
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import jsonl_bytes, model_bytes
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.models.contracts import InventoryEntry, TargetSnapshot

ROOT = Path(__file__).resolve().parents[2]
CASE = ROOT / "test_cases/development/artifact-inventory/case.json"


def metadata(paths: tuple[str, ...]) -> tuple[TargetSnapshot, tuple[InventoryEntry, ...]]:
    entries = tuple(
        InventoryEntry(path=path, sha256="a" * 64, byte_length=3, media_type="text/plain")
        for path in paths
    )
    content_hash = semantic_hash(
        cast(
            JsonValue,
            [{"path": e.path, "sha256": e.sha256, "byte_length": e.byte_length} for e in entries],
        )
    )
    return (
        TargetSnapshot(
            target_id="target_authored",
            snapshot_id=f"snapshot_{content_hash}",
            source_kind="project-fixture",
            source_label="authored-unit-metadata",
            revision="authored-v1",
            retrieved_at=datetime(2026, 10, 2, tzinfo=UTC),
            license_status="project-authored-private",
            content_sha256=content_hash,
            inventory_sha256=sha256_bytes(jsonl_bytes(entries)),
            file_count=len(entries),
            total_bytes=sum(e.byte_length for e in entries),
        ),
        entries,
    )


def report_payload() -> dict[str, Any]:
    snapshot, entries = metadata(("agent.py", "README.md"))
    return build_artifact_inventory(snapshot, entries).model_dump(mode="json")


def test_authored_case_retains_every_file_without_reading_or_executing_it(tmp_path: Path) -> None:
    case = json.loads(CASE.read_bytes())
    source = tmp_path / "target"
    expected = {}
    for file in case["files"]:
        path = source / file["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(file["text"], encoding="utf-8")
        expected[file["path"]] = tuple(file["expected_recognizers"])
    snapshot = create_snapshot(
        source, tmp_path / "snapshots", source_label=case["case_id"], revision="authored-v1"
    )
    # Recognition receives metadata only; even a missing content directory cannot
    # become an accidental target read or execution in this layer.
    snapshot.content_root.rename(snapshot.snapshot_root / "not-available-to-recognizer")
    report = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    assert {r.source.path: r.recognizer_ids for r in report.records} == expected
    assert {f.family: f.candidate_file_count for f in report.families} == case[
        "expected_family_counts"
    ]
    assert sum(not r.recognizer_ids for r in report.records) == case["expected_unclassified_files"]
    assert tuple(r.source for r in report.records) == snapshot.inventory
    assert all(r.parse_state == r.analysis_state == "not-run" for r in report.records)
    assert all(r.finding_count is None for r in report.records)
    assert report.content_reverification == "not-performed"
    assert report.repository_completeness == "not-verified"
    assert report.scan_authorization == "not-granted"
    assert ArtifactInventory.model_validate_json(model_bytes(report)) == report
    assert model_bytes(report) == model_bytes(
        build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    )


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "skill.md",
        "AGENTS.md.txt",
        "agent.PY",
        "tool.pyc",
        "main.tfvars",
        "main.tf.json.bak",
        "langgraph.json.template",
        "pyproject.toml",
        "config.json",
        "memory.json",
        "permissions.json",
        "prompts/system.txt",
        "deploy.yaml",
    ],
)
def test_unrecognized_names_are_not_reclassified_by_guessing(path: str) -> None:
    assert match_path(path) == ()
    snapshot, entries = metadata((path,))
    report = build_artifact_inventory(snapshot, entries)
    assert len(report.records) == 1
    assert report.records[0].recognizer_ids == ()


def test_empty_inventory_retains_unknown_unsupported_families() -> None:
    snapshot, entries = metadata(())
    report = build_artifact_inventory(snapshot, entries)
    assert report.records == ()
    for family in report.families:
        if family.family in ("memory-context", "identity-permissions"):
            assert family.candidate_file_count is None
            assert family.interpretation == "unknown"
        else:
            assert family.candidate_file_count == 0
            assert family.interpretation == "no-candidate-recognized"


@pytest.mark.parametrize("paths", [("a.py", "a.py"), ("a.py", "A.py")])
def test_duplicate_or_case_colliding_metadata_is_refused(paths: tuple[str, ...]) -> None:
    snapshot, entries = metadata(paths)
    with pytest.raises(ValueError, match="colliding"):
        build_artifact_inventory(snapshot, entries)


@pytest.mark.parametrize("path", ["CON.py", "x/aux.json", "x./a.py", "x/a:stream", "."])
def test_nonportable_metadata_paths_are_refused(path: str) -> None:
    snapshot, entries = metadata((path,))
    with pytest.raises(ValueError):
        build_artifact_inventory(snapshot, entries)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file_count", 0),
        ("total_bytes", 999),
        ("inventory_sha256", "b" * 64),
        ("content_sha256", "b" * 64),
        ("snapshot_id", "snapshot_wrong"),
    ],
)
def test_inconsistent_snapshot_is_refused(field: str, value: Any) -> None:
    snapshot, entries = metadata(("agent.py",))
    setattr(snapshot, field, value)
    with pytest.raises(ValueError, match="match"):
        build_artifact_inventory(snapshot, entries)


def test_original_intake_order_is_preserved_not_sorted() -> None:
    snapshot, entries = metadata(("z.py", "root.txt", "a/nested.py"))
    report = build_artifact_inventory(snapshot, entries)
    assert tuple(r.source.path for r in report.records) == tuple(e.path for e in entries)
    with pytest.raises(ValueError, match="inventory hash"):
        build_artifact_inventory(snapshot, tuple(reversed(entries)))


@pytest.mark.parametrize("revision", ["main", "v1.0", "1234abc", "A" * 40])
def test_git_metadata_requires_full_revision_identity(revision: str) -> None:
    snapshot, entries = metadata(("agent.py",))
    snapshot.source_kind = "git"
    snapshot.revision = revision
    with pytest.raises(ValueError, match="full revision"):
        build_artifact_inventory(snapshot, entries)


def test_pinned_git_metadata_is_not_git_tree_verification() -> None:
    snapshot, entries = metadata(("agent.py",))
    snapshot.source_kind = "git"
    snapshot.revision = "a" * 40
    report = build_artifact_inventory(snapshot, entries)
    assert report.repository_completeness == "not-verified"


def test_input_models_are_detached_and_later_report_mutations_are_detected() -> None:
    snapshot, entries = metadata(("agent.py",))
    report = build_artifact_inventory(snapshot, entries)
    entries[0].sha256 = "b" * 64
    snapshot.total_bytes = 999
    assert report.records[0].source.sha256 == "a" * 64
    assert report.snapshot.total_bytes == 3
    report.records[0].source.byte_length = 100
    with pytest.raises(ValidationError, match="counts"):
        artifact_inventory_semantic_sha256(report)


def test_semantic_hash_excludes_only_retrieved_time() -> None:
    snapshot, entries = metadata(("agent.py",))
    first = build_artifact_inventory(snapshot, entries)
    snapshot.retrieved_at += timedelta(hours=1)
    second = build_artifact_inventory(snapshot, entries)
    assert model_bytes(first) != model_bytes(second)
    assert artifact_inventory_semantic_sha256(first) == artifact_inventory_semantic_sha256(second)
    snapshot.revision = "authored-v2"
    third = build_artifact_inventory(snapshot, entries)
    assert artifact_inventory_semantic_sha256(first) != artifact_inventory_semantic_sha256(third)


@pytest.mark.parametrize("mutation", ["rule", "family", "id", "catalog", "source", "missing-file"])
def test_derivative_tampering_is_rejected(mutation: str) -> None:
    payload = report_payload()
    if mutation == "rule":
        payload["records"][0]["recognizer_ids"] = []
    elif mutation == "family":
        payload["families"][0]["candidate_file_count"] = 999
    elif mutation == "id":
        payload["records"][0]["artifact_id"] = "artifact_invented"
    elif mutation == "catalog":
        payload["recognizers"][0]["pattern"] = ".txt"
    elif mutation == "source":
        payload["records"][0]["source"]["sha256"] = "b" * 64
    else:
        payload["records"].pop()
    with pytest.raises(ValidationError):
        ArtifactInventory.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [("parse_state", "parsed"), ("analysis_state", "complete"), ("finding_count", 0)],
)
def test_filename_matching_cannot_become_completed_security_analysis(
    field: str, value: Any
) -> None:
    payload = report_payload()
    payload["records"][0][field] = value
    with pytest.raises(ValidationError):
        ArtifactInventory.model_validate(payload)


def test_inventory_resource_bound_is_explicit() -> None:
    snapshot, entries = metadata(("agent.py",))
    with pytest.raises(ValueError, match="file-count limit"):
        build_artifact_inventory(snapshot, entries * (MAX_INVENTORY_FILES + 1))


@pytest.mark.parametrize("path", ["./agent.py", "a/../agent.py", "folder\\agent.py"])
def test_serialized_derivative_rejects_noncanonical_source_spelling(path: str) -> None:
    payload = report_payload()
    payload["records"][0]["source"]["path"] = path
    with pytest.raises(ValidationError):
        ArtifactInventory.model_validate(payload)


@pytest.mark.parametrize("count", [True, "1", 1.0])
def test_family_count_is_not_coerced_to_an_integer(count: Any) -> None:
    payload = report_payload()
    payload["families"][0]["candidate_file_count"] = count
    with pytest.raises(ValidationError):
        ArtifactInventory.model_validate(payload)


def test_every_recognizer_has_traceable_support_and_a_limit() -> None:
    assert len({r.recognizer_id for r in RECOGNIZERS}) == len(RECOGNIZERS)
    for rule in RECOGNIZERS:
        assert rule.reference and rule.limitation
        assert rule.recognizer_id in match_path(
            "nested/" + ("example" if rule.selector == "suffix" else "") + rule.pattern
        )
