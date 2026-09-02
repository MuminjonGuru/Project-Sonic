from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec_evidence.adapters.kics import (
    KicsParseError,
    NormalizedKics,
    normalize_kics,
    parse_kics_json,
)
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.execution.config import KicsToolConfig, load_toml_config


def _fixture(name: str) -> bytes:
    return (Path(__file__).resolve().parents[1] / "fixtures" / "kics" / name).read_bytes()


def _tool() -> KicsToolConfig:
    root = Path(__file__).resolve().parents[2]
    return load_toml_config(root / "configs" / "tools" / "kics.toml", KicsToolConfig).value


def _normalize(name: str) -> NormalizedKics:
    data = _fixture(name)
    return normalize_kics(
        parse_kics_json(data),
        tool=_tool(),
        run_id="run_test",
        execution_id="execution_test",
        target_snapshot_id="snapshot_test",
        source_blob_sha256=sha256_bytes(data),
    )


def test_parser_and_normalizer_preserve_native_evidence() -> None:
    data = _fixture("finding.json")
    parsed = parse_kics_json(data)
    normalized = normalize_kics(
        parsed,
        tool=_tool(),
        run_id="run_test",
        execution_id="execution_test",
        target_snapshot_id="snapshot_test",
        source_blob_sha256=sha256_bytes(data),
    )

    assert parsed.native_result_count == 2
    assert parsed.unknown_fields == ()
    assert len(normalized.findings) == 2
    findings = {finding.rule.native_id: finding for finding in normalized.findings}

    privileged = findings["dd29336b-fe57-445b-a26e-e6aa867ae609"]
    assert privileged.locations[0].artifact_path == "privileged-pod.yaml"
    assert privileged.locations[0].start_line == 10
    assert privileged.rule.mappings[0].taxonomy == "CWE"
    assert privileged.rule.mappings[0].value == "269"
    assert privileged.severity.normalized == "high"
    assert privileged.evidence[0].json_pointer == "/queries/0/files/0"
    assert privileged.evidence[0].blob_sha256 == sha256_bytes(data)
    assert privileged.fingerprints.native

    public_acl = findings["d0cc8694-fcad-43ff-ac86-32331d7e867f"]
    assert public_acl.locations[0].artifact_path == "vulnerable.tf"
    assert public_acl.rule.mappings[0].value == "284"
    assert public_acl.severity.normalized == "medium"
    assert public_acl.assessment.exposure_statement == "static-observable-condition"
    assert normalized.failures == ()
    assert normalized.coverage[0].observation == "observed-risk"


def test_clean_result_is_not_described_as_safe() -> None:
    normalized = _normalize("clean.json")

    assert normalized.findings == ()
    assert normalized.failures == ()
    assert normalized.coverage[0].execution == "success"
    assert normalized.coverage[0].observation == "no-observation"
    assert "not safe" in normalized.coverage[0].limitations[-1]


def test_parser_counter_deficit_is_explicit_partial_evidence() -> None:
    normalized = _normalize("partial-parse.json")

    assert normalized.findings == ()
    assert len(normalized.failures) == 1
    assert normalized.failures[0].category == "configuration"
    assert normalized.failures[0].partial_evidence_usable is False
    assert normalized.coverage[0].execution == "partial"
    assert normalized.coverage[0].observation == "no-observation"


def test_unsupported_target_is_not_treated_as_clean() -> None:
    normalized = _normalize("unsupported.json")

    assert normalized.findings == ()
    assert normalized.failures == ()
    coverage = normalized.coverage[0]
    assert coverage.applicability == "not-applicable"
    assert coverage.adapter_support == "unsupported"
    assert coverage.execution == "not-run"
    assert coverage.observation == "unknown"


def test_unknown_fields_are_counted_without_discarding_known_evidence() -> None:
    document = json.loads(_fixture("finding.json"))
    document["future_top_level_field"] = True
    document["queries"][0]["future_query_field"] = {"value": 1}
    document["queries"][0]["files"][0]["future_file_field"] = "preserved"

    parsed = parse_kics_json(json.dumps(document).encode())

    assert parsed.unknown_fields == (
        "/future_top_level_field",
        "/queries/0/files/0/future_file_field",
        "/queries/0/future_query_field",
    )


@pytest.mark.parametrize(
    "data",
    [
        _fixture("malformed.json"),
        b'{"kics_version":"v2.1.20","kics_version":"v2.1.19"}',
        b'{"kics_version":"v2.1.20","risk":NaN}',
        b"[]",
    ],
)
def test_malformed_or_ambiguous_json_fails_explicitly(data: bytes) -> None:
    with pytest.raises(KicsParseError):
        parse_kics_json(data)


def test_finding_outside_the_controlled_mount_is_rejected() -> None:
    document = json.loads(_fixture("finding.json"))
    document["queries"][0]["files"][0]["file_name"] = "../../../host/secret.txt"
    data = json.dumps(document).encode()

    with pytest.raises(KicsParseError, match="outside the controlled target mount"):
        normalize_kics(
            parse_kics_json(data),
            tool=_tool(),
            run_id="run_test",
            execution_id="execution_test",
            target_snapshot_id="snapshot_test",
            source_blob_sha256=sha256_bytes(data),
        )
