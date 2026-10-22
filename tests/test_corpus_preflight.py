from __future__ import annotations

import ast
import importlib.util
import io
import json
import socket
import subprocess
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_model, json_bytes
from agentsec_evidence.intake.corpus import (
    CorpusCandidate,
    CorpusCandidates,
    build_preview,
    load_candidates,
    path_role,
    verify_preview,
    write_preview,
)
from agentsec_evidence.intake.git_verification import git_object_oid
from agentsec_evidence.intake.repository import RepositoryIntakeSpec, prepare_repository

PROJECT = Path(__file__).resolve().parents[1]


def prepared(
    root: Path, files: dict[str, bytes]
) -> tuple[CorpusCandidate, RepositoryIntakeSpec, Path]:
    root.mkdir(exist_ok=True)
    tree: list[dict[str, Any]] = []

    def directory(prefix: str) -> str:
        direct: list[tuple[str, str, str]] = []
        children = sorted({p[len(prefix) :].split("/")[0] for p in files if p.startswith(prefix)})
        for name in children:
            full = prefix + name
            if full in files:
                oid = git_object_oid("blob", files[full])
                tree.append(
                    {
                        "path": full,
                        "mode": "100644",
                        "type": "blob",
                        "sha": oid,
                        "size": len(files[full]),
                    }
                )
                direct.append((name, "100644", oid))
            else:
                oid = directory(full + "/")
                tree.append({"path": full, "mode": "040000", "type": "tree", "sha": oid})
                direct.append((name, "40000", oid))
        ordered = sorted(direct, key=lambda e: (e[0] + ("/" if e[1] == "40000" else "")).encode())
        raw = b"".join(
            mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
            for name, mode, oid in ordered
        )
        return git_object_oid("tree", raw)

    tree_id = directory("")
    commit = (
        f"tree {tree_id}\nauthor Test <test@example.invalid> 1 +0000\n"
        "committer Test <test@example.invalid> 1 +0000\n\nAuthored test\n"
    ).encode()
    revision = git_object_oid("commit", commit)
    cache = root / "cache"
    cache.mkdir()
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, raw in files.items():
            archive.writestr("authored/" + path, raw)
    (cache / "source.zip").write_bytes(data.getvalue())
    (cache / "commit.bin").write_bytes(commit)
    (cache / "tree-exact.json").write_bytes(
        json_bytes({"sha": tree_id, "truncated": False, "tree": cast(JsonValue, tree)})
    )
    candidate = CorpusCandidate(
        candidate_id="R03",
        repository="authored/corpus-test",
        revision=revision,
        kind="mcp",
        role="prospective-descriptive-candidate",
        prescreen_files=len(files),
        prescreen_python_files=sum(p.endswith(".py") for p in files),
        reported_license="unknown",
        selection_rationale="Authored preflight test only",
        lineage_note="Authored test; not public evidence",
    )
    spec = RepositoryIntakeSpec(
        source_label=candidate.url,
        revision=revision,
        root_tree=tree_id,
        archive_sha256=sha256_file(cache / "source.zip"),
        raw_commit_sha256=sha256_file(cache / "commit.bin"),
        tree_response_sha256=sha256_file(cache / "tree-exact.json"),
        expected_files=len(files),
        expected_bytes=sum(map(len, files.values())),
        license_status="unknown",
        role="formative-pilot",
    )
    target = root / "prepared"
    prepare_repository(spec, cache=cache, output=target)
    return candidate, spec, target


def test_preview_offline_replay_no_source_parser_or_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Preflight must not parse Python, launch processes or use the network")

    monkeypatch.setattr(ast, "parse", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    candidate, spec, target = prepared(
        tmp_path,
        {
            "tool.py": b"bad syntax(",
            "tests/test_tool.py": b"pass\n",
            "LICENSE": b"Authored license placeholder",
        },
    )
    before = {
        p.relative_to(target).as_posix(): sha256_file(p) for p in target.rglob("*") if p.is_file()
    }
    result = build_preview(candidate, spec, target)
    assert result.scanner_invocations == 0 and result.syntax_validation == "not-performed"
    assert result.scanning_authorization == "not-granted"
    assert len(result.selection) == 2 and len(result.license_candidates) == 1
    assert result.license_review == "pending-source-specific-review"
    assert all(s.state == "pending-validation" and s.findings is None for s in result.stages)
    output = tmp_path / "preview"
    write_preview(result, output)
    assert verify_preview(output, candidate, spec, target) == result
    with pytest.raises(FileExistsError):
        write_preview(result, output)
    assert before == {
        p.relative_to(target).as_posix(): sha256_file(p) for p in target.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize(
    "count, baseline_state, batches",
    [
        (1, "pending-validation", 1),
        (64, "pending-validation", 1),
        (65, "unsupported-size", 2),
        (130, "unsupported-size", 3),
    ],
)
def test_full_selection_never_silently_shards_baselines(
    tmp_path: Path, count: int, baseline_state: str, batches: int
) -> None:
    candidate, spec, target = prepared(
        tmp_path, {f"src/f{i:03}.py": b"pass\n" for i in range(count)}
    )
    result = build_preview(candidate, spec, target)
    assert len(result.selection) == count
    assert len(result.custom_partitions) == batches
    assert sorted(p for batch in result.custom_partitions for p in batch) == sorted(
        e.source.path for e in result.selection
    )
    assert all(s.state == baseline_state for s in result.stages[1:])
    assert all(s.selected_files == count for s in result.stages)


def test_semgrep_policy_counts_toward_whole_view_budget(tmp_path: Path) -> None:
    files = {f"f{i}.py": b"pass\n" for i in range(64)}
    files[".semgrepignore"] = b"tests/\n"
    candidate, spec, target = prepared(tmp_path, files)
    result = build_preview(candidate, spec, target)
    assert result.stages[1].state == "unsupported-size"
    assert result.stages[1].policy_files == 1
    assert result.stages[2].state == "pending-validation"


@pytest.mark.parametrize(
    "path, raw, index",
    [(".agent-audit.yaml", b"rules: []", 2), (".semgrepignore", b":include ../outside\n", 1)],
)
def test_policy_refusal_is_not_clean(tmp_path: Path, path: str, raw: bytes, index: int) -> None:
    candidate, spec, target = prepared(tmp_path, {"a.py": b"pass", path: raw})
    result = build_preview(candidate, spec, target)
    assert result.stages[index].state == "policy-refused"
    assert result.stages[index].findings is None


def test_individual_oversize_retains_selection_and_exclusion(tmp_path: Path) -> None:
    candidate, spec, target = prepared(
        tmp_path, {"big.py": b"#" * (256 * 1024 + 1), "small.py": b"pass"}
    )
    result = build_preview(candidate, spec, target)
    assert len(result.selection) == 2
    assert result.selection[0].custom_size_state == "unsupported-file-size"
    assert result.custom_partitions == (("small.py",),)
    assert result.stages[0].reasons
    assert all(s.state == "unsupported-size" for s in result.stages[1:])


def test_aggregate_byte_limit_does_not_change_selection(tmp_path: Path) -> None:
    candidate, spec, target = prepared(
        tmp_path, {f"f{i}.py": b"#" * (230 * 1024) for i in range(5)}
    )
    result = build_preview(candidate, spec, target)
    assert len(result.custom_partitions) == 2
    assert all("combined-bytes-exceed-1-MiB" in s.reasons for s in result.stages[1:])


def test_no_python_no_findings(tmp_path: Path) -> None:
    candidate, spec, target = prepared(tmp_path, {"README.md": b"test", "mcp.json": b"{}"})
    result = build_preview(candidate, spec, target)
    assert result.custom_partitions == ()
    assert all(s.state == "no-input" and s.findings is None for s in result.stages)
    assert result.optional_artifact_candidates["mcp-json-name-candidates"] == ("mcp.json",)


@pytest.mark.parametrize("field", ["selection", "partitions", "stages", "license", "source"])
def test_changed_derivative_rejected(tmp_path: Path, field: str) -> None:
    candidate, spec, target = prepared(tmp_path, {"a.py": b"pass\n"})
    result = build_preview(candidate, spec, target)
    output = tmp_path / "preview"
    write_preview(result, output)
    value = result.model_dump(mode="json")
    if field == "selection":
        value["selection"][0]["path_role"] = "tests"
    elif field == "partitions":
        value["custom_partitions"] = []
    elif field == "stages":
        value["stages"][0]["selected_files"] = 0
    elif field == "license":
        value["license_candidates"] = [value["selection"][0]["source"]]
    else:
        value["source_content_sha256"] = "0" * 64
    (output / "preview.json").write_bytes(json_bytes(value))
    with pytest.raises(ValueError, match="differs"):
        verify_preview(output, candidate, spec, target)


def test_parent_tamper_and_wrong_candidate_refused(tmp_path: Path) -> None:
    candidate, spec, target = prepared(tmp_path, {"a.py": b"pass"})
    with pytest.raises(ValueError, match="selected candidate"):
        build_preview(candidate.model_copy(update={"repository": "wrong/other"}), spec, target)
    with pytest.raises(ValueError, match="formative"):
        build_preview(candidate, spec.model_copy(update={"role": "demo"}), target)
    (target / "source/a.py").write_bytes(b"different")
    with pytest.raises(ValueError):
        build_preview(candidate, spec, target)


def test_prescreen_differences_are_explicit(tmp_path: Path) -> None:
    candidate, spec, target = prepared(tmp_path, {"a.py": b"pass"})
    candidate = candidate.model_copy(update={"prescreen_files": 3, "prescreen_python_files": 2})
    assert len(build_preview(candidate, spec, target).metadata_differences) == 2


@pytest.mark.parametrize(
    "path, expected",
    [
        (".github/scripts/check.py", "ci"),
        ("tests/unit/case.py", "tests"),
        ("test_tool.py", "tests"),
        ("examples/tool.py", "examples"),
        ("docs/script.py", "documentation"),
        ("src/tool.py", "other-source"),
    ],
)
def test_path_roles_are_only_heuristics(path: str, expected: str) -> None:
    assert path_role(path) == expected


def test_recorded_candidate_manifest(tmp_path: Path) -> None:
    manifest = load_candidates(PROJECT / "test_cases/corpus/candidates-2026-10-21.json")
    assert len(manifest.candidates) == 20
    assert sum(c.role == "existing-formative-pilot" for c in manifest.candidates) == 2
    assert sum(c.kind == "mcp" for c in manifest.candidates) == 8
    atomic_write_model(tmp_path / "manifest.json", manifest)
    assert load_candidates(tmp_path / "manifest.json") == manifest
    value = manifest.model_dump(mode="json")
    value["candidates"][1]["repository"] = value["candidates"][0]["repository"].upper()
    with pytest.raises(ValueError, match="unique"):
        CorpusCandidates.model_validate(value)


def test_extra_preview_file_refused(tmp_path: Path) -> None:
    candidate, spec, target = prepared(tmp_path, {"a.py": b"pass"})
    output = tmp_path / "preview"
    write_preview(build_preview(candidate, spec, target), output)
    (output / "extra").write_text("not authorized")
    with pytest.raises(ValueError, match="membership"):
        verify_preview(output, candidate, spec, target)


def test_generated_schemas_match_and_validate(tmp_path: Path) -> None:
    from agentsec_evidence.intake.corpus import CorpusPreview

    candidate, spec, target = prepared(tmp_path, {"a.py": b"pass"})
    preview = build_preview(candidate, spec, target)
    registry = load_candidates(PROJECT / "test_cases/corpus/candidates-2026-10-21.json")
    for model, name, value in (
        (CorpusCandidates, "candidates", registry),
        (CorpusPreview, "preview", preview),
    ):
        schema = json.loads(
            (PROJECT / f"schemas/corpus-preflight-v1/{name}.schema.json").read_bytes()
        )
        generated = model.model_json_schema(mode="serialization")
        generated["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        generated["$id"] = f"urn:agentsec-evidence:schema:corpus-preflight-{name}-v1"
        assert generated == schema
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value.model_dump(mode="json"))


@pytest.mark.parametrize("mode", ["success", "private", "wrong-commit", "bad-archive"])
def test_online_helper_retains_failure_and_never_launches_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    candidate, intake, _ = prepared(tmp_path / "fixture", {"a.py": b"pass"})
    module_spec = importlib.util.spec_from_file_location(
        "corpus_acquire_test", PROJECT / "tools/acquire_corpus_candidate.py"
    )
    assert module_spec and module_spec.loader
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    calls = []
    cache = tmp_path / "fixture/cache"

    def fake_capture(root: Path, label: str, argv: list[str], **kwargs: Any) -> bytes:
        calls.append((label, argv))
        assert argv[0] in {"gh", "git"}
        if label == "metadata":
            return json_bytes({"full_name": candidate.repository, "private": mode == "private"})
        if label == "commit":
            return json_bytes(
                {
                    "sha": "0" * 40 if mode == "wrong-commit" else candidate.revision,
                    "tree": {"sha": intake.root_tree},
                    "verification": None,
                }
            )
        if label == "tree":
            return (cache / "tree-exact.json").read_bytes()
        if label in {"git-init", "git-fetch"}:
            return b""
        if label == "git-commit":
            return (cache / "commit.bin").read_bytes()
        if label == "archive":
            return b"not zip" if mode == "bad-archive" else (cache / "source.zip").read_bytes()
        raise AssertionError(label)

    monkeypatch.setattr(module, "capture", fake_capture)
    output = tmp_path / "attempt"
    if mode == "success":
        module.acquire(candidate, output)
        status = json.loads((output / "status.json").read_bytes())
        assert status["state"] == "prepared-previewed-not-admitted"
        assert verify_preview(output / "preflight", candidate, intake, output / "prepared")
        assert all("checkout" not in argv and "clone" not in argv for _, argv in calls)
    else:
        with pytest.raises((ValueError, zipfile.BadZipFile)):
            module.acquire(candidate, output)
        status = json.loads((output / "status.json").read_bytes())
        assert status["state"] == "failed" and status["error"]
    assert status["scanner_invocations"] == 0 and status["findings"] is None
    assert (output / "acquisition-manifest.json").is_file()
    with pytest.raises(FileExistsError):
        module.acquire(candidate, output)
