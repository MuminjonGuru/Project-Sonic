from __future__ import annotations

from pathlib import Path

import pytest

from agentsec_evidence.adapters.semgrep import (
    SemgrepParseError,
    normalize_semgrep,
    parse_semgrep_json,
)
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.execution.config import SemgrepToolConfig, load_toml_config


def _fixture(name: str) -> bytes:
    return (Path(__file__).resolve().parents[1] / "fixtures" / "semgrep" / name).read_bytes()


def _tool() -> SemgrepToolConfig:
    root = Path(__file__).resolve().parents[2]
    return load_toml_config(root / "configs" / "tools" / "semgrep.toml", SemgrepToolConfig).value


def test_parser_and_normalizer_preserve_provenance() -> None:
    data = _fixture("finding.json")
    parsed = parse_semgrep_json(data)
    normalized = normalize_semgrep(
        parsed,
        tool=_tool(),
        run_id="run_test",
        execution_id="execution_test",
        target_snapshot_id="snapshot_test",
        source_blob_sha256=sha256_bytes(data),
    )

    assert parsed.unknown_top_level_fields == (
        "engine_requested",
        "future_additive_field",
    )
    assert len(normalized.findings) == 1
    finding = normalized.findings[0]
    assert finding.rule.native_id == "project.first-slice.python-eval"
    assert finding.locations[0].artifact_path == "vulnerable.py"
    assert finding.evidence[0].json_pointer == "/results/0"
    assert finding.evidence[0].blob_sha256 == sha256_bytes(data)
    assert finding.severity.native_label == "ERROR"
    assert finding.severity.normalized == "high"
    assert normalized.coverage[0].observation == "observed-risk"


def test_clean_result_is_not_described_as_safe() -> None:
    data = _fixture("clean.json")
    normalized = normalize_semgrep(
        parse_semgrep_json(data),
        tool=_tool(),
        run_id="run_test",
        execution_id="execution_test",
        target_snapshot_id="snapshot_test",
        source_blob_sha256=sha256_bytes(data),
    )

    assert normalized.findings == ()
    assert normalized.coverage[0].observation == "no-observation"
    assert "not safe" in normalized.coverage[0].limitations[0]


def test_malformed_json_fails_explicitly() -> None:
    with pytest.raises(SemgrepParseError):
        parse_semgrep_json(_fixture("malformed.json"))


def test_duplicate_json_keys_fail_explicitly() -> None:
    with pytest.raises(SemgrepParseError, match="Duplicate JSON key"):
        parse_semgrep_json(b'{"version":"1","version":"2","results":[],"errors":[],"paths":{}}')
