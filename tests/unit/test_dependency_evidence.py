from __future__ import annotations

import copy
import sys
import zipfile
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.analysis import (
    compare_stages,
    dependency_semantic_hash,
    fraction,
)
from agentsec_evidence.dependencies.database import inspect_database
from agentsec_evidence.dependencies.execution import build_dependency_argv
from agentsec_evidence.dependencies.models import DependencyScope, StageEvidence
from agentsec_evidence.dependencies.mutations import Mutation, mutate_sbom
from agentsec_evidence.dependencies.parsers import (
    parse_cyclonedx,
    parse_lockfile,
    parse_osv,
    parse_syft,
)
from agentsec_evidence.dependencies.pipeline import seal_bundle, validate_dependency_bundle
from agentsec_evidence.dependencies.validation import validate_cyclonedx
from agentsec_evidence.execution.process import run_bounded_process

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "test_cases/development/dependency-basic/target"


def bom() -> dict[str, JsonValue]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": "requests-old",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            }
        ],
        "dependencies": [{"ref": "requests-old", "dependsOn": []}],
    }


def scope() -> DependencyScope:
    return DependencyScope(
        input_sha256="a" * 64,
        eligible=[("requests", "2.31.0")],
        separate_local=[],
        unsupported_pointers=[],
        ambiguous_projections=[],
    )


def osv_data(*, with_findings: bool = True) -> bytes:
    package: dict[str, JsonValue] = {
        "package": {"name": "Requests", "version": "2.31.0", "ecosystem": "PyPI"}
    }
    if with_findings:
        package["vulnerabilities"] = [{"id": "GHSA-test"}, {"id": "PYSEC-test"}]
    return json_bytes({"results": [{"source": {"path": "/src/uv.lock"}, "packages": [package]}]})


def test_lock_scope_keeps_versions_groups_markers_and_local_root() -> None:
    stage, result = parse_lockfile((TARGET / "uv.lock").read_bytes())
    assert len(stage.observations) == 5
    assert len(result.eligible) == 4
    assert ("requests", "2.31.0") in result.eligible
    assert ("requests", "2.33.0") in result.eligible
    assert result.separate_local == [("sonic-fixture", "0.0.0")]
    assert any(item.context.get("resolution-markers") for item in stage.observations)
    assert any(edge.context["group"] == "dev-dependencies:dev" for edge in stage.relationships)


@pytest.mark.parametrize("case", ["dependency-malformed", "dependency-unsupported"])
def test_invalid_lockfiles_do_not_become_empty_clean_inventories(case: str) -> None:
    with pytest.raises(ValueError):
        parse_lockfile((ROOT / "test_cases/development" / case / "target/uv.lock").read_bytes())


def test_unresolved_versions_and_private_registry_are_not_guessed() -> None:
    data = b'version=1\n[[package]]\nname="requests"\nsource={registry="https://pypi.org/simple"}\n'
    stage, result = parse_lockfile(data)
    assert stage.observations[0].status == "unresolved"
    assert not result.eligible and len(result.unsupported_pointers) == 1
    data += b'[[package]]\nname="requests"\nversion="2.31.0"\nsource={registry="https://private.invalid/simple"}\n'
    assert not parse_lockfile(data)[1].eligible


def test_same_projection_different_sources_is_ambiguous() -> None:
    data = (
        b'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\n'
        b'source={registry="https://pypi.org/simple"}\n[[package]]\nname="requests"\n'
        b'version="2.31.0"\nsource={editable="."}\n'
    )
    _, result = parse_lockfile(data)
    assert result.ambiguous_projections == [("requests", "2.31.0")]
    assert not result.eligible


def test_duplicate_occurrences_do_not_inflate_unique_identity_counts() -> None:
    document = bom()
    components = cast(list[JsonValue], document["components"])
    second = copy.deepcopy(cast(dict[str, JsonValue], components[0]))
    second["bom-ref"] = "another-occurrence"
    components.append(second)
    stage = parse_cyclonedx(json_bytes(document))
    result = compare_stages(stage, stage, scope())
    assert len(stage.observations) == 2
    assert (
        result.package_projection_retention and result.package_projection_retention.denominator == 1
    )


@pytest.mark.parametrize("mutation", ["remove-component", "remove-purl", "change-version"])
def test_mutations_preserve_original_and_expose_handoff_changes(mutation: Mutation) -> None:
    original = json_bytes(bom())
    changed = mutate_sbom(original, mutation)
    validate_cyclonedx(changed, ROOT / "schemas/vendor/cyclonedx/1.6")
    left, right = parse_cyclonedx(original), parse_cyclonedx(changed)
    result = compare_stages(left, right, scope())
    assert json_bytes(bom()) == original
    assert result.missing == [("requests", "2.31.0")]
    if mutation == "remove-purl":
        assert result.missing_identifiers == ["/components/0"]
        assert right.observations[0].status == "unsupported"
    elif mutation == "change-version":
        assert right.observations[0].version == "2.32.5"
        assert not right.observations[0].limitations


def test_conflicting_version_and_purl_are_not_equivalent() -> None:
    document = bom()
    cast(dict[str, JsonValue], cast(list[JsonValue], document["components"])[0])["version"] = (
        "2.33.0"
    )
    assert parse_cyclonedx(json_bytes(document)).observations[0].status == "conflicting"


def test_schema_and_dangling_relationship_validation() -> None:
    document = bom()
    document["dependencies"] = [{"ref": "requests-old", "dependsOn": ["missing"]}]
    with pytest.raises(ValueError, match="Dangling"):
        validate_cyclonedx(json_bytes(document), ROOT / "schemas/vendor/cyclonedx/1.6")
    document["specVersion"] = "99"
    with pytest.raises(ValueError):
        parse_cyclonedx(json_bytes(document))


@pytest.mark.parametrize(
    "exit_code,state",
    [(1, "complete"), (127, "failed"), (128, "unsupported"), (42, "failed"), (0, "partial")],
)
def test_osv_exit_and_findings_are_separate(exit_code: int, state: str) -> None:
    aliases: dict[str, tuple[str, ...]] = {
        identifier: ("CVE-TEST", "GHSA-test", "PYSEC-test")
        for identifier in ("GHSA-test", "PYSEC-test")
    }
    result = parse_osv(
        osv_data(), stage_name="osv-direct", exit_code=exit_code, alias_groups=aliases
    )
    assert result.state == state
    assert len(result.matches) == 1
    assert result.matches[0].original_ids == ["GHSA-test", "PYSEC-test"]
    assert result.matches[0].canonical_advisory == "CVE-TEST"


def test_clean_output_is_only_a_reported_package_not_matching_proof() -> None:
    result = parse_osv(
        osv_data(with_findings=False), stage_name="osv-direct", exit_code=0, alias_groups={}
    )
    assert result.state == "complete" and len(result.observations) == 1
    assert not result.matches
    assert "matching completion" in result.limitations[0]
    failed = parse_osv(
        osv_data(with_findings=False), stage_name="osv-direct", exit_code=127, alias_groups={}
    )
    assert not compare_stages(result, failed, scope()).comparable
    assert compare_stages(result, failed, scope()).package_projection_retention is None


def test_missing_frozen_alias_record_is_partial_not_invented_aliasing() -> None:
    assert (
        parse_osv(osv_data(), stage_name="osv-direct", exit_code=1, alias_groups={}).state
        == "partial"
    )


def test_syft_schema_and_source_qualifier_loss() -> None:
    document: dict[str, JsonValue] = {
        "schema": {"version": "16.1.10"},
        "artifacts": [
            {
                "id": "a",
                "name": "requests",
                "version": "2.31.0",
                "type": "python",
                "purl": "pkg:pypi/requests@2.31.0",
                "metadata": {"index": "https://pypi.org/simple"},
            }
        ],
    }
    result = compare_stages(
        parse_syft(json_bytes(document)), parse_cyclonedx(json_bytes(bom())), scope()
    )
    assert result.package_projection_retention and result.package_projection_retention.value == 1
    assert result.source_qualifier_losses == [("requests", "2.31.0")]
    document["schema"] = {"version": "17.0"}
    with pytest.raises(ValueError):
        parse_syft(json_bytes(document))


def test_semantic_projection_ignores_raw_hash_but_keeps_status_and_version() -> None:
    stage = parse_cyclonedx(json_bytes(bom()))
    before = dependency_semantic_hash([stage], scope())
    stage.raw_sha256 = "b" * 64
    assert before == dependency_semantic_hash([stage], scope())
    stage.state = "failed"
    assert before != dependency_semantic_hash([stage], scope())
    assert fraction(0, 0).value is None


def test_database_hash_entry_hashes_and_transitive_aliases(tmp_path: Path) -> None:
    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("one.json", json_bytes({"id": "ONE", "aliases": ["TWO"], "affected": []}))
        output.writestr("two.json", json_bytes({"id": "TWO", "aliases": ["THREE"], "affected": []}))
    result = inspect_database(archive, sha256_file(archive), set())
    assert result.aliases["ONE"] == ("ONE", "THREE", "TWO")
    assert len(result.entries) == 2
    with pytest.raises(ValueError, match="hash-mismatched"):
        inspect_database(archive, "0" * 64, set())


def test_dependency_bundle_detects_tamper_and_extra_files(tmp_path: Path) -> None:
    (tmp_path / "record.json").write_text("{}", encoding="utf-8")
    (tmp_path / "database").mkdir()
    (tmp_path / "database/manifest.json").write_text("{}", encoding="utf-8")
    seal_bundle(tmp_path)
    assert validate_dependency_bundle(tmp_path)["passed"]
    (tmp_path / "extra").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="Unmanifested"):
        validate_dependency_bundle(tmp_path)
    (tmp_path / "extra").unlink()
    (tmp_path / "record.json").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        validate_dependency_bundle(tmp_path)


def test_docker_plan_has_no_target_install_network_or_mutable_image(tmp_path: Path) -> None:
    source = tmp_path / "uv.lock"
    source.write_text("version=1", encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text("", encoding="utf-8")
    database = tmp_path / "all.zip"
    database.write_bytes(b"test")
    argv = build_dependency_argv(
        docker=Path(sys.executable),
        name="sonic-dep-test",
        producer="osv",
        input_file=source,
        output=tmp_path,
        config=config,
        database=database,
    )
    assert argv[argv.index("--network") + 1] == "none"
    assert "--offline" in argv and "--no-resolve" in argv and "--no-call-analysis=all" in argv
    assert any("osv-scanner@sha256:" in item for item in argv)
    assert any("/database/osv-scalibr/PyPI/all.zip,readonly" in item for item in argv)
    assert not any("docker.sock" in item for item in argv)


def test_generated_file_limit_marks_fast_process_output_limited(tmp_path: Path) -> None:
    output = tmp_path / "generated.bin"
    capture = run_bounded_process(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; Path('generated.bin').write_bytes(b'x'*2048)",
        ],
        cwd=tmp_path,
        environment={},
        timeout_seconds=10,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
        monitored_files=[output],
        max_generated_bytes=1024,
    )
    assert capture.output_limited


def test_empty_inventory_is_not_100_percent() -> None:
    stage = StageEvidence(stage="syft", raw_sha256="0" * 64)
    result = compare_stages(stage, stage, scope())
    assert result.package_projection_retention and result.package_projection_retention.value is None


def test_syft_extras_order_is_semantically_irrelevant_but_content_is_not() -> None:
    stage = parse_cyclonedx(json_bytes(bom()))
    stage.stage = "syft"
    stage.observations[0].context = {
        "metadata": {
            "extras": [
                {"name": "test", "dependencies": ["pytest", "rich"]},
                {"name": "otel", "dependencies": ["opentelemetry-api"]},
            ]
        }
    }
    original = stage.model_copy(deep=True)
    changed = stage.model_copy(deep=True)
    metadata = cast(dict[str, JsonValue], changed.observations[0].context["metadata"])
    extras = cast(list[JsonValue], metadata["extras"])
    extras.reverse()
    cast(dict[str, JsonValue], extras[1])["dependencies"] = ["rich", "pytest"]
    assert dependency_semantic_hash([stage], scope()) == dependency_semantic_hash(
        [changed], scope()
    )
    assert dependency_semantic_hash([stage], scope(), version="dependency-semantic-v1") != (
        dependency_semantic_hash([changed], scope(), version="dependency-semantic-v1")
    )
    assert stage == original  # Semantic projection must never rewrite retained observations.
    cast(dict[str, JsonValue], extras[1])["dependencies"] = ["rich", "new-package"]
    assert dependency_semantic_hash([stage], scope()) != dependency_semantic_hash(
        [changed], scope()
    )
    changed = stage.model_copy(deep=True)
    changed.observations[0].version = "2.33.0"
    assert dependency_semantic_hash([stage], scope()) != dependency_semantic_hash(
        [changed], scope()
    )


def test_empty_success_is_partial_and_missing_alias_cannot_downgrade_failure() -> None:
    empty = parse_osv(b'{"results":[]}', stage_name="osv-direct", exit_code=0, alias_groups={})
    assert empty.state == "partial"
    failed = parse_osv(osv_data(), stage_name="osv-direct", exit_code=127, alias_groups={})
    assert failed.state == "failed"
