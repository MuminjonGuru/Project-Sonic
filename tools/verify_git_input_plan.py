"""Reproduce the fixed authored Git verification and selection case; never scan a target."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.core.io import (
    atomic_write_bytes,
    atomic_write_model,
    json_bytes,
    model_bytes,
)
from agentsec_evidence.intake.git_verification import (
    GitSourceVerification,
    bind_inventory_to_git,
    replay_git_verification,
    verify_git_source,
)
from agentsec_evidence.intake.input_plan import (
    ToolInputPlan,
    build_tool_input_plan,
    verify_tool_input_plan,
)
from agentsec_evidence.intake.snapshot import create_snapshot

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "test_cases/development/pinned-git/case.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New, unused evidence directory")
    output = parser.parse_args().output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    case = json.loads(CASE.read_bytes())
    commit = case["raw_commit"].encode("utf-8")
    tree = json_bytes(case["tree"])
    profile = json_bytes(case["profile"])
    files = {canonical_artifact_path(f["path"]): f["text"].encode("utf-8") for f in case["files"]}
    atomic_write_bytes(output / "raw/commit.bin", commit)
    atomic_write_bytes(output / "raw/tree.json", tree)
    atomic_write_bytes(output / "raw/profile.json", profile)
    proof = verify_git_source(
        raw_commit=commit, raw_tree=tree, revision=case["revision"], files=files
    )
    atomic_write_model(output / "git-verification.json", proof)
    repeated = verify_git_source(
        raw_commit=commit, raw_tree=tree, revision=case["revision"], files=files
    )
    atomic_write_model(output / "git-verification-repeat.json", repeated)
    if (
        model_bytes(proof) != model_bytes(repeated)
        or len(proof.files) != case["expected_file_count"]
    ):
        raise RuntimeError("Git verification count or repetition did not match")
    source = output / "authored-source"
    for path, data in files.items():
        atomic_write_bytes(source / path, data)
    snapshot = create_snapshot(
        source,
        output / "snapshots",
        source_label="authored-pinned-git-case",
        revision=case["revision"],
        source_kind="git",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    atomic_write_model(output / "artifact-inventory.json", inventory)
    bind_inventory_to_git(inventory, proof)
    plan_arguments = dict(
        inventory=inventory,
        verification=proof,
        tool_id="authored-python-selection",
        profile_id=case["profile"]["profile_id"],
        profile_bytes=profile,
        selected_paths=case["selected_python_paths"],
        selected_reason="Authored Python input view",
        exclusions={
            path: "Outside authored Python input view; retained in inventory"
            for path in files
            if path not in case["selected_python_paths"]
        },
    )
    plan = build_tool_input_plan(**plan_arguments)  # type: ignore[arg-type]
    atomic_write_model(output / "input-plan.json", plan)
    plan_repeat = build_tool_input_plan(**plan_arguments)  # type: ignore[arg-type]
    atomic_write_model(output / "input-plan-repeat.json", plan_repeat)
    if model_bytes(plan) != model_bytes(plan_repeat):
        raise RuntimeError("Input plan repetition changed")
    restored_proof = GitSourceVerification.model_validate_json(
        (output / "git-verification.json").read_bytes()
    )
    copied_files = {
        e.path: (snapshot.content_root / e.path).read_bytes() for e in snapshot.inventory
    }
    replay_git_verification(
        restored_proof,
        raw_commit=(output / "raw/commit.bin").read_bytes(),
        raw_tree=(output / "raw/tree.json").read_bytes(),
        files=copied_files,
    )
    restored_plan = ToolInputPlan.model_validate_json((output / "input-plan.json").read_bytes())
    verify_tool_input_plan(
        restored_plan,
        inventory,
        restored_proof,
        profile_bytes=(output / "raw/profile.json").read_bytes(),
    )
    selected = [s.path for s in plan.selections if s.disposition == "selected"]
    if sorted(selected) != sorted(case["selected_python_paths"]):
        raise RuntimeError("Authored selected-path expectations differ")
    summary = {
        "passed": True,
        "split": "development-only",
        "case_sha256": sha256_file(CASE),
        "revision": proof.revision,
        "tree": proof.root_tree,
        "files_verified": len(proof.files),
        "files_accounted_for": len(plan.selections),
        "selected_files": len(selected),
        "excluded_files": len(plan.selections) - len(selected),
        "git_verification_sha256": semantic_hash(proof.model_dump(mode="json")),
        "input_plan_sha256": semantic_hash(plan.model_dump(mode="json")),
        "repeated_bytes_equal": True,
        "snapshot_copy_reverified": True,
        "scanner_executed": False,
        "target_code_executed": False,
        "policy_and_suppression_review": "not-performed",
        "execution_authorization": "not-granted",
        "independent_review": "not-performed",
    }
    atomic_write_bytes(output / "summary.json", json_bytes(summary))
    entries = [
        {
            "path": path.relative_to(output).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    ]
    atomic_write_bytes(output / "evidence-manifest.json", json_bytes({"files": entries}))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
