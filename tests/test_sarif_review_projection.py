"""Authored projection controls; no public target or scanner execution."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema.exceptions import ValidationError

from agentsec_evidence.core.identity import sha256_bytes

PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "tools/sarif_review_projection.py"
SCHEMA = PROJECT / "schemas/vendor/oasis/sarif-schema-2.1.0.json"
spec = importlib.util.spec_from_file_location("sarif_review_projection", SCRIPT)
assert spec is not None and spec.loader is not None
projection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(projection)


@pytest.fixture
def log() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "properties": {"original": "preserved"},
        "runs": [
            {
                "tool": {"driver": {"name": "authored-control", "version": "1.0"}},
                "invocations": [{"executionSuccessful": False}],
                "properties": {"repetition": 1, "analysis": "partial"},
                "results": [
                    {
                        "kind": "review",
                        "level": "error",
                        "ruleId": "EXAMPLE-001",
                        "message": {"text": "unreviewed <claim>"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "space%20name/inert.py"},
                                    "region": {"startLine": 2, "startColumn": 3},
                                }
                            }
                        ],
                        "partialFingerprints": {"original": "identity"},
                        "suppressions": [{"kind": "external", "status": "underReview"}],
                        "properties": {
                            "nativeSeverity": "critical",
                            "nativeConfidence": 0.1,
                            "nativeTier": "SUPPRESSED",
                            "nativeSuppressed": False,
                        },
                    }
                ],
            }
        ],
    }


def generated(log: dict[str, Any]) -> dict[str, bytes]:
    raw = projection.encoded(log)
    return cast(dict[str, bytes], projection.project(raw, sha256_bytes(raw), SCHEMA))


def package(tmp_path: Path, log: dict[str, Any]) -> tuple[Path, str]:
    source = tmp_path / "original" / "source.sarif"
    source.parent.mkdir()
    raw = projection.encoded(log)
    source.write_bytes(raw)
    output = tmp_path / "corrected"
    projection.write(source, sha256_bytes(raw), output, SCHEMA)
    assert source.read_bytes() == raw
    return output, sha256_bytes(raw)


def rehash(output: Path, name: str) -> None:
    manifest = json.loads((output / "evidence-manifest.json").read_bytes())
    raw = (output / name).read_bytes()
    manifest["files"][name] = {"bytes": len(raw), "sha256": sha256_bytes(raw)}
    (output / "evidence-manifest.json").write_bytes(projection.encoded(manifest))


@pytest.mark.parametrize("level", ["error", "warning", "note"])
def test_corrects_only_review_level(log: dict[str, Any], level: str) -> None:
    original = log["runs"][0]["results"][0]
    original["level"] = level
    before = copy.deepcopy(log)
    files = generated(log)
    corrected = json.loads(files["results.sarif"])
    result = corrected["runs"][0]["results"][0]
    assert result["level"] == "none" and result["kind"] == "review"
    prior = result["properties"].pop(projection.PRIOR)
    assert prior["value"] == level
    result["level"] = level
    corrected["properties"].pop(projection.META)
    assert corrected == log == before
    assert files["source.sarif"] == projection.encoded(log)
    ledger = json.loads(files["correction.json"])
    assert ledger["changed_results"] == ledger["review_records"] == 1
    assert ledger["changes"][0]["pointer"] == "/runs/0/results/0"
    assert not ledger["human_acceptance"] and not ledger["native_replayed"]


@pytest.mark.parametrize(
    "mode", ["none", "absent", "fail", "kind-absent", "empty", "no-results", "no-runs"]
)
def test_valid_results_are_not_relabelled(log: dict[str, Any], mode: str) -> None:
    result = log["runs"][0]["results"][0]
    if mode == "none":
        result["level"] = "none"
    elif mode == "absent":
        del result["level"]
    elif mode == "fail":
        result["kind"] = "fail"
    elif mode == "kind-absent":
        del result["kind"]
    elif mode == "empty":
        log["runs"][0]["results"] = []
    elif mode == "no-results":
        del log["runs"][0]["results"]
    else:
        log["runs"] = []
    files = generated(log)
    result_log = json.loads(files["results.sarif"])
    result_log["properties"].pop(projection.META)
    assert result_log == log
    assert json.loads(files["correction.json"])["changed_results"] == 0


def test_multiple_runs_positions_and_missing_properties(log: dict[str, Any]) -> None:
    del log["properties"]
    del log["runs"][0]["results"][0]["properties"]
    log["runs"].append(copy.deepcopy(log["runs"][0]))
    log["runs"][1]["results"].insert(0, {"kind": "fail", "message": {"text": "untouched"}})
    files = generated(log)
    ledger = json.loads(files["correction.json"])
    assert ledger["result_records"] == 3
    assert [c["pointer"] for c in ledger["changes"]] == ["/runs/0/results/0", "/runs/1/results/1"]
    assert all(not c["properties_were_present"] for c in ledger["changes"])


@pytest.mark.parametrize(
    "bad",
    [
        "bad-hash",
        "wrong-hash",
        "schema",
        "rank",
        "other-kind",
        "log-collision",
        "result-collision",
        "null-results",
    ],
)
def test_rejects_unsupported_projection(log: dict[str, Any], tmp_path: Path, bad: str) -> None:
    schema = SCHEMA
    if bad == "rank":
        log["runs"][0]["results"][0]["rank"] = 5.0
    elif bad == "other-kind":
        log["runs"][0]["results"][0]["kind"] = "pass"
    elif bad == "log-collision":
        log["properties"][projection.META] = "existing"
    elif bad == "result-collision":
        log["runs"][0]["results"][0]["properties"][projection.PRIOR] = "existing"
    elif bad == "null-results":
        log["runs"][0]["results"] = None
    elif bad == "schema":
        schema = tmp_path / "schema.json"
        schema.write_bytes(b"{}")
    raw = projection.encoded(log)
    expected = (
        "bad" if bad == "bad-hash" else "0" * 64 if bad == "wrong-hash" else sha256_bytes(raw)
    )
    with pytest.raises((ValueError, ValidationError)):
        projection.project(raw, expected, schema)


@pytest.mark.parametrize(
    "raw", [b'{"version":"2.1.0","version":"2.1.0"}', b'{"x":NaN}', b"[]", b"\xff"]
)
def test_strict_json(raw: bytes) -> None:
    with pytest.raises(ValueError):
        projection.project(raw, sha256_bytes(raw), SCHEMA)


def test_reprojection_is_refused(log: dict[str, Any]) -> None:
    corrected = generated(log)["results.sarif"]
    with pytest.raises(ValueError, match="Already projected"):
        projection.project(corrected, sha256_bytes(corrected), SCHEMA)


def test_no_overwrite_or_nested_output(tmp_path: Path, log: dict[str, Any]) -> None:
    output, digest = package(tmp_path, log)
    source = tmp_path / "original/source.sarif"
    with pytest.raises(ValueError, match="Fresh output"):
        projection.write(source, digest, output, SCHEMA)
    with pytest.raises(ValueError, match="outside"):
        projection.write(source, digest, source.parent / "nested", SCHEMA)
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(ValueError, match="outside"):
        projection.write(source, digest, staging / "../original/nested", SCHEMA)


@pytest.mark.parametrize("name", ["results.sarif", "correction.json", "README.md", "source.sarif"])
def test_rehashed_tampering_does_not_pass(tmp_path: Path, log: dict[str, Any], name: str) -> None:
    output, digest = package(tmp_path, log)
    if name == "README.md":
        (output / name).write_bytes(b"Human approved; no limitations")
    else:
        data = json.loads((output / name).read_bytes())
        if name == "correction.json":
            data["human_acceptance"] = True
        else:
            data["runs"][0]["results"][0]["message"]["text"] = "altered"
        (output / name).write_bytes(projection.encoded(data))
    rehash(output, name)
    with pytest.raises(ValueError):
        projection.verify(output, digest, SCHEMA)


@pytest.mark.parametrize("mode", ["extra", "missing", "manifest-metadata", "manifest-path"])
def test_membership_and_manifest(tmp_path: Path, log: dict[str, Any], mode: str) -> None:
    output, digest = package(tmp_path, log)
    if mode == "extra":
        (output / "unexpected.txt").write_text("extra")
    elif mode == "missing":
        (output / "README.md").unlink()
    else:
        manifest = json.loads((output / "evidence-manifest.json").read_bytes())
        if mode == "manifest-metadata":
            manifest["human_acceptance"] = True
        else:
            manifest["files"]["../outside"] = manifest["files"].pop("README.md")
        (output / "evidence-manifest.json").write_bytes(projection.encoded(manifest))
    with pytest.raises(ValueError):
        projection.verify(output, digest, SCHEMA)


def test_hardlinked_source_refused(tmp_path: Path, log: dict[str, Any]) -> None:
    original = tmp_path / "original.sarif"
    original.write_bytes(projection.encoded(log))
    alias = tmp_path / "alias.sarif"
    os.link(original, alias)
    with pytest.raises(ValueError, match="non-hard-linked"):
        projection.write(alias, sha256_bytes(alias.read_bytes()), tmp_path / "output", SCHEMA)


def test_size_budget_before_output(tmp_path: Path) -> None:
    source = tmp_path / "source.sarif"
    source.write_bytes(b" " * (projection.MAX_ENTRY_BYTES + 1))
    with pytest.raises(ValueError, match="byte limit"):
        projection.write(source, "0" * 64, tmp_path.parent / (tmp_path.name + "-out"), SCHEMA)


def test_cli_and_portable_verification(tmp_path: Path, log: dict[str, Any]) -> None:
    output, digest = package(tmp_path, log)
    relocated = tmp_path / "relocated"
    output.rename(relocated)
    result = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8",
            str(SCRIPT),
            "verify",
            "--output",
            str(relocated),
            "--source-sha256",
            digest,
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    receipt = json.loads(result.stdout)
    assert receipt["passed"] and receipt["changed_results"] == 1
    assert receipt["scanner_invocations"] == 0 and not receipt["native_replayed"]
