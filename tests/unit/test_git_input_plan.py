from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsec_evidence.agents.inventory import ArtifactInventory, build_artifact_inventory
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.core.io import json_bytes, model_bytes
from agentsec_evidence.intake import git_verification as git_module
from agentsec_evidence.intake.git_verification import (
    GitSourceVerification,
    GitVerificationError,
    UnsupportedGitInput,
    bind_inventory_to_git,
    git_object_oid,
    replay_git_verification,
    verify_git_source,
)
from agentsec_evidence.intake.input_plan import (
    ToolInputPlan,
    build_tool_input_plan,
    verify_tool_input_plan,
)
from agentsec_evidence.intake.snapshot import SnapshotPolicy, create_snapshot

ROOT = Path(__file__).resolve().parents[2]
CASE = ROOT / "test_cases/development/pinned-git/case.json"


def case_args() -> dict[str, Any]:
    case = json.loads(CASE.read_bytes())
    return {
        "raw_commit": case["raw_commit"].encode(),
        "raw_tree": json_bytes(case["tree"]),
        "revision": case["revision"],
        "files": {f["path"]: f["text"].encode() for f in case["files"]},
    }


def one_file(data: bytes, name: str = "file.txt") -> dict[str, Any]:
    def oid(kind: str, value: bytes) -> str:
        return hashlib.sha1(
            f"{kind} {len(value)}\0".encode() + value, usedforsecurity=False
        ).hexdigest()

    blob = oid("blob", data)
    tree = oid("tree", b"100644 " + name.encode() + b"\0" + bytes.fromhex(blob))
    commit = f"tree {tree}\nauthor Test <test@example.invalid> 0 +0000\n\nAuthored\n".encode()
    return {
        "raw_commit": commit,
        "revision": oid("commit", commit),
        "raw_tree": json_bytes(
            {
                "sha": tree,
                "truncated": False,
                "tree": [
                    {"path": name, "sha": blob, "mode": "100644", "type": "blob", "size": len(data)}
                ],
            }
        ),
        "files": {name: data},
    }


def bound_case(tmp_path: Path) -> tuple[ArtifactInventory, GitSourceVerification, bytes]:
    args = case_args()
    proof = verify_git_source(**args)
    source = tmp_path / "authored"
    for name, data in args["files"].items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    snapshot = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="authored-git-case",
        revision=args["revision"],
        source_kind="git",
    )
    report = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    profile = json_bytes(json.loads(CASE.read_bytes())["profile"])
    return report, proof, profile


def make_plan(
    report: ArtifactInventory, proof: GitSourceVerification, profile: bytes
) -> ToolInputPlan:
    selected = json.loads(CASE.read_bytes())["selected_python_paths"]
    return build_tool_input_plan(
        inventory=report,
        verification=proof,
        tool_id="authored-tool",
        profile_id="authored-python-v1",
        profile_bytes=profile,
        selected_paths=selected,
        selected_reason="Authored Python view",
        exclusions={
            r.source.path: "Outside this authored Python view"
            for r in report.records
            if r.source.path not in selected
        },
    )


def test_git_encoded_fixture_verifies_and_preserves_all_paths_and_modes() -> None:
    args = case_args()
    proof = verify_git_source(**args)
    assert proof.revision == "3320a4620c57670428ba2cfa21837d8529bf9d86"
    assert proof.root_tree == "a992c161bf17eb5e0f85940841f9e7444c8bf059"
    assert len(proof.files) == 21
    assert {f.source.path for f in proof.files} == set(args["files"])
    assert next(f for f in proof.files if f.source.path == "agent.py").source.mode == "100755"
    assert proof.execution_authorization == "not-granted"
    assert proof.origin_authentication == "not-established"
    assert model_bytes(proof) == model_bytes(verify_git_source(**args))
    replay_git_verification(
        GitSourceVerification.model_validate_json(model_bytes(proof)),
        **{k: v for k, v in args.items() if k != "revision"},
    )


def test_known_git_blob_and_empty_tree_identities() -> None:
    assert git_object_oid("blob", b"test content\n") == "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
    assert git_object_oid("tree", b"") == "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@pytest.mark.parametrize("fault", ["missing", "extra", "changed", "line-endings"])
def test_missing_extra_or_changed_source_is_rejected(fault: str) -> None:
    args = case_args()
    if fault == "missing":
        del args["files"]["README.md"]
    elif fault == "extra":
        args["files"]["untracked.txt"] = b"extra"
    elif fault == "changed":
        args["files"]["README.md"] = b"changed"
    else:
        args["files"]["README.md"] = args["files"]["README.md"].replace(b"\n", b"\r\n")
    with pytest.raises(GitVerificationError):
        verify_git_source(**args)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-file",
        "missing-tree",
        "wrong-root",
        "wrong-child",
        "wrong-mode",
        "wrong-size",
        "wrong-blob",
    ],
)
def test_tree_lies_are_not_accepted_from_matching_top_level_fields(fault: str) -> None:
    args = case_args()
    tree = json.loads(args["raw_tree"])
    blob = next(e for e in tree["tree"] if e["type"] == "blob")
    directory = next(e for e in tree["tree"] if e["type"] == "tree")
    if fault == "missing-file":
        tree["tree"].remove(blob)
    elif fault == "missing-tree":
        tree["tree"].remove(directory)
    elif fault == "wrong-root":
        tree["sha"] = "a" * 40
    elif fault == "wrong-child":
        directory["sha"] = "a" * 40
    elif fault == "wrong-mode":
        blob["mode"] = "100755" if blob["mode"] == "100644" else "100644"
    elif fault == "wrong-size":
        blob["size"] += 1
    else:
        blob["sha"] = "a" * 40
    args["raw_tree"] = json_bytes(tree)
    with pytest.raises(GitVerificationError):
        verify_git_source(**args)


@pytest.mark.parametrize("flag", [True, None, "false", 0])
def test_tree_requires_literal_false_truncation_flag(flag: Any) -> None:
    args = case_args()
    tree = json.loads(args["raw_tree"])
    tree["truncated"] = flag
    args["raw_tree"] = json_bytes(tree)
    with pytest.raises(GitVerificationError, match="non-truncated"):
        verify_git_source(**args)


@pytest.mark.parametrize(
    ("kind", "mode"), [("blob", "120000"), ("commit", "160000"), ("blob", "100664")]
)
def test_unsupported_entry_is_explicit(kind: str, mode: str) -> None:
    args = case_args()
    tree = json.loads(args["raw_tree"])
    tree["tree"][0].update(type=kind, mode=mode)
    args["raw_tree"] = json_bytes(tree)
    with pytest.raises(UnsupportedGitInput):
        verify_git_source(**args)


@pytest.mark.parametrize(
    "version", ["https://git-lfs.github.com/spec/v1", "https://hawser.github.com/spec/v1"]
)
def test_lfs_is_refused_even_when_pointer_bytes_match_git(version: str) -> None:
    data = f"version {version}\noid sha256:{'a' * 64}\nsize 100\n".encode()
    with pytest.raises(UnsupportedGitInput, match="LFS"):
        verify_git_source(**one_file(data))


def test_lfs_mention_inside_a_document_is_not_a_pointer() -> None:
    proof = verify_git_source(**one_file(b"Document\nversion https://git-lfs.github.com/spec/v1\n"))
    assert len(proof.files) == 1


@pytest.mark.parametrize(
    "path",
    [
        "../file",
        "./file",
        "/file",
        "C:/file",
        "a\\b",
        "AUX.txt",
        ".git/config",
        "x/.GIT/config",
        "a./file",
        "a/" * 65 + "file",
    ],
)
def test_unsafe_or_noncanonical_tree_paths_are_rejected(path: str) -> None:
    args = case_args()
    tree = json.loads(args["raw_tree"])
    tree["tree"][0]["path"] = path
    args["raw_tree"] = json_bytes(tree)
    with pytest.raises(ValueError):
        verify_git_source(**args)


@pytest.mark.parametrize(
    "path",
    ["COM\u00b9.txt", "LPT\u00b2", "com\u00b3.log", "CON .txt", "aux .json"],
)
def test_windows_reserved_names_are_refused_even_with_valid_git_objects(path: str) -> None:
    with pytest.raises(ValueError, match=r"[Rr]eserved"):
        verify_git_source(**one_file(b"controlled input\n", path))


@pytest.mark.parametrize("path", ["COM10.txt", "company.txt", "notes\u00b9.txt"])
def test_similar_nonreserved_names_remain_supported(path: str) -> None:
    proof = verify_git_source(**one_file(b"", path))
    assert proof.files[0].source.path == path
    assert proof.files[0].source.size == 0


@pytest.mark.parametrize(
    "fault",
    ["duplicate", "case-collision", "size-bool", "size-missing", "directory-size", "duplicate-key"],
)
def test_ambiguous_metadata_is_rejected(fault: str) -> None:
    args = case_args()
    tree = json.loads(args["raw_tree"])
    blob = next(e for e in tree["tree"] if e["type"] == "blob")
    if fault in ("duplicate", "case-collision"):
        extra = copy.deepcopy(blob)
        if fault == "case-collision":
            extra["path"] = extra["path"].upper()
        tree["tree"].append(extra)
    elif fault == "size-bool":
        blob["size"] = True
    elif fault == "size-missing":
        del blob["size"]
    elif fault == "directory-size":
        next(e for e in tree["tree"] if e["type"] == "tree")["size"] = 0
    args["raw_tree"] = json_bytes(tree)
    if fault == "duplicate-key":
        args["raw_tree"] = args["raw_tree"].replace(
            b'"truncated": false', b'"truncated": true, "truncated": false'
        )
    with pytest.raises(ValueError):
        verify_git_source(**args)


@pytest.mark.parametrize("revision", ["main", "123abc", "A" * 40, "a" * 64])
def test_moving_short_or_unsupported_revision_is_refused(revision: str) -> None:
    args = case_args()
    args["revision"] = revision
    with pytest.raises(UnsupportedGitInput):
        verify_git_source(**args)


def test_changed_commit_is_rejected() -> None:
    args = case_args()
    args["raw_commit"] += b"changed"
    with pytest.raises(GitVerificationError, match="pinned revision"):
        verify_git_source(**args)


@pytest.mark.parametrize("fault", ["no-separator", "duplicate-tree", "not-first"])
def test_commit_header_ambiguity_is_rejected_even_with_correct_oid(fault: str) -> None:
    args = case_args()
    raw = args["raw_commit"]
    if fault == "no-separator":
        raw = raw.replace(b"\n\n", b"\n")
    elif fault == "duplicate-tree":
        raw = raw.split(b"\n", 1)[0] + b"\n" + raw
    else:
        raw = b"parent " + b"a" * 40 + b"\n" + raw
    args["raw_commit"] = raw
    args["revision"] = hashlib.sha1(
        f"commit {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    with pytest.raises(GitVerificationError):
        verify_git_source(**args)


def test_nonrecursive_tree_response_cannot_claim_completeness() -> None:
    args = case_args()
    tree = json.loads(args["raw_tree"])
    tree["tree"] = [e for e in tree["tree"] if "/" not in e["path"]]
    args["raw_tree"] = json_bytes(tree)
    with pytest.raises(GitVerificationError, match="Reconstructed tree"):
        verify_git_source(**args)


@pytest.mark.parametrize(
    "limit", ["commit", "tree-bytes", "tree-entries", "files", "file-bytes", "total-bytes"]
)
def test_verifier_resource_limits_are_enforced(monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    if limit == "commit":
        monkeypatch.setattr(git_module, "MAX_COMMIT_BYTES", 1)
    elif limit == "tree-bytes":
        monkeypatch.setattr(git_module, "MAX_TREE_BYTES", 1)
    elif limit == "tree-entries":
        monkeypatch.setattr(git_module, "MAX_TREE_ENTRIES", 1)
    else:
        policies = {
            "files": SnapshotPolicy(max_files=1),
            "file-bytes": SnapshotPolicy(max_file_bytes=1),
            "total-bytes": SnapshotPolicy(max_total_bytes=1),
        }
        policy = policies[limit]
        monkeypatch.setattr(git_module, "SnapshotPolicy", lambda: policy)
    with pytest.raises(ValueError):
        verify_git_source(**case_args())


def test_empty_git_tree_is_verified_without_inventing_files() -> None:
    root = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    raw = f"tree {root}\n\nAuthored empty tree\n".encode()
    revision = hashlib.sha1(
        f"commit {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    proof = verify_git_source(
        raw_commit=raw,
        raw_tree=json_bytes({"sha": root, "truncated": False, "tree": []}),
        revision=revision,
        files={},
    )
    assert proof.files == ()


def test_snapshot_link_rejects_different_source_or_revision(tmp_path: Path) -> None:
    report, proof, _profile = bound_case(tmp_path)
    report.snapshot.revision = "a" * 40
    with pytest.raises(GitVerificationError, match="revision"):
        bind_inventory_to_git(report, proof)


def test_snapshot_link_rejects_missing_verified_file(tmp_path: Path) -> None:
    report, proof, _profile = bound_case(tmp_path)
    payload = proof.model_dump(mode="json")
    payload["files"].pop()
    with pytest.raises(GitVerificationError, match="inventory"):
        bind_inventory_to_git(report, GitSourceVerification.model_validate(payload))


def test_reordered_api_entries_do_not_change_the_verified_git_tree() -> None:
    args = case_args()
    first = verify_git_source(**args)
    tree = json.loads(args["raw_tree"])
    tree["tree"].reverse()
    args["raw_tree"] = json_bytes(tree)
    second = verify_git_source(**args)
    assert first.files == second.files and first.root_tree == second.root_tree
    assert first.tree_response_sha256 != second.tree_response_sha256


def test_loaded_receipt_tampering_requires_raw_replay() -> None:
    args = case_args()
    proof = verify_git_source(**args)
    payload = proof.model_dump(mode="json")
    payload["files"][0]["sha256"] = "a" * 64
    changed = GitSourceVerification.model_validate(payload)
    with pytest.raises(GitVerificationError, match="receipt"):
        replay_git_verification(changed, **{k: v for k, v in args.items() if k != "revision"})


def test_bound_plan_accounts_for_every_file_without_admission(tmp_path: Path) -> None:
    report, proof, profile = bound_case(tmp_path)
    plan = make_plan(report, proof, profile)
    bind_inventory_to_git(report, proof)
    assert len(plan.selections) == 21
    assert sum(s.disposition == "selected" for s in plan.selections) == 5
    assert {s.path for s in plan.selections} == {r.source.path for r in report.records}
    assert (
        next(s for s in plan.selections if s.path == ".agent-audit.yaml").disposition == "excluded"
    )
    assert plan.policy_and_suppression_review == "not-performed"
    assert plan.execution_authorization == "not-granted" and plan.parser_validation == "not-run"
    assert model_bytes(plan) == model_bytes(make_plan(report, proof, profile))
    verify_tool_input_plan(
        ToolInputPlan.model_validate_json(model_bytes(plan)), report, proof, profile_bytes=profile
    )


@pytest.mark.parametrize(
    "fault", ["missing", "extra", "wrong-hash", "wrong-inventory", "wrong-proof", "wrong-profile"]
)
def test_plan_cannot_hide_or_rebind_inputs(tmp_path: Path, fault: str) -> None:
    report, proof, profile = bound_case(tmp_path)
    payload = make_plan(report, proof, profile).model_dump(mode="json")
    if fault == "missing":
        payload["selections"].pop()
    elif fault == "extra":
        extra = dict(payload["selections"][-1], path="zzz.extra")
        payload["selections"].append(extra)
    elif fault == "wrong-hash":
        payload["selections"][0]["source_sha256"] = "a" * 64
    elif fault == "wrong-inventory":
        payload["artifact_inventory_semantic_sha256"] = "a" * 64
    elif fault == "wrong-proof":
        payload["git_verification_sha256"] = "a" * 64
    else:
        profile = b"changed profile"
    with pytest.raises(ValueError):
        verify_tool_input_plan(
            ToolInputPlan.model_validate(payload), report, proof, profile_bytes=profile
        )


@pytest.mark.parametrize("fault", ["blank-reason", "duplicate", "overlap", "missing", "extra"])
def test_selection_builder_requires_explicit_unambiguous_decisions(
    tmp_path: Path, fault: str
) -> None:
    report, proof, profile = bound_case(tmp_path)
    selected = ["agent.py"]
    excluded = {
        r.source.path: "Excluded by authored treatment"
        for r in report.records
        if r.source.path != "agent.py"
    }
    if fault == "blank-reason":
        excluded["README.md"] = "  "
    elif fault == "duplicate":
        selected.append("agent.py")
    elif fault == "overlap":
        excluded["agent.py"] = "Conflicting choice"
    elif fault == "missing":
        del excluded["README.md"]
    else:
        selected.append("absent.py")
    with pytest.raises(ValueError):
        build_tool_input_plan(
            inventory=report,
            verification=proof,
            tool_id="authored",
            profile_id="v1",
            profile_bytes=profile,
            selected_paths=selected,
            selected_reason="Authored",
            exclusions=excluded,
        )


def test_different_selection_changes_plan_identity_without_changing_inventory(
    tmp_path: Path,
) -> None:
    report, proof, profile = bound_case(tmp_path)
    before = model_bytes(report)
    first = make_plan(report, proof, profile)
    second = build_tool_input_plan(
        inventory=report,
        verification=proof,
        tool_id="authored-tool",
        profile_id="none",
        profile_bytes=profile,
        selected_paths=[],
        selected_reason="Unused",
        exclusions={
            r.source.path: "No selected inputs in this authored case" for r in report.records
        },
    )
    assert model_bytes(report) == before
    assert semantic_hash(first.model_dump(mode="json")) != semantic_hash(
        second.model_dump(mode="json")
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("execution_authorization", "approved"),
        ("parser_validation", "complete"),
        ("policy_and_suppression_review", "complete"),
    ],
)
def test_selection_cannot_be_promoted_to_scanner_permission(
    tmp_path: Path, field: str, value: str
) -> None:
    report, proof, profile = bound_case(tmp_path)
    payload = make_plan(report, proof, profile).model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        ToolInputPlan.model_validate(payload)
