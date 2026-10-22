"""Explicit online preparation only: pinned GitHub bytes, no scanners or target execution."""

from __future__ import annotations

import argparse
import os
from dataclasses import asdict
from pathlib import Path

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model, json_bytes
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.intake.corpus import (
    CorpusCandidate,
    build_preview,
    load_candidates,
    verify_preview,
    write_preview,
)
from agentsec_evidence.intake.git_verification import GitVerificationError, git_object_oid
from agentsec_evidence.intake.repository import RepositoryIntakeSpec, prepare_repository
from agentsec_evidence.intake.source_archive import recover_github_commit
from agentsec_evidence.research.retained import plain_path


def capture(root: Path, label: str, argv: list[str], *, limit: int = 4 * 1024**2) -> bytes:
    env = dict(os.environ)
    env.update({"GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"})
    if argv[0] == "git":
        env = {k: v for k, v in env.items() if not k.startswith("GIT_")}
        env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
            }
        )
    result = run_bounded_process(
        argv,
        cwd=root,
        environment=env,
        timeout_seconds=120,
        max_stdout_bytes=limit,
        max_stderr_bytes=256 * 1024,
    )
    atomic_write_bytes(root / "acquisition" / (label + ".stdout"), result.stdout)
    atomic_write_bytes(root / "acquisition" / (label + ".stderr"), result.stderr)
    record = asdict(result)
    record.pop("stdout")
    record.pop("stderr")
    record["started_at"] = result.started_at.isoformat()
    record["ended_at"] = result.ended_at.isoformat()
    atomic_write_bytes(root / "acquisition" / (label + ".json"), json_bytes(record))
    if result.exit_code != 0 or result.timed_out or result.output_limited:
        raise ValueError("Acquisition failed or exceeded its bounds: " + label)
    return result.stdout


def acquire(candidate: CorpusCandidate, output: Path) -> None:
    plain_path(output.parent, directory=True)
    output.mkdir(exist_ok=False)
    atomic_write_model(output / "candidate.json", candidate)
    state = "failed"
    error = None
    try:
        base = "repos/" + candidate.repository
        meta = load_agent_json(
            capture(output, "metadata", ["gh", "api", base]), max_bytes=4 * 1024**2
        )
        if (
            meta.get("private") is not False
            or str(meta.get("full_name")).casefold() != candidate.repository.casefold()
        ):
            raise ValueError("Repository visibility or canonical name differs from selection")
        raw_commit_response = capture(
            output, "commit", ["gh", "api", base + "/git/commits/" + candidate.revision]
        )
        commit = load_agent_json(raw_commit_response, max_bytes=4 * 1024**2)
        if commit.get("sha") != candidate.revision or not isinstance(commit.get("tree"), dict):
            raise ValueError("GitHub commit does not identify the selected revision")
        tree_id = commit["tree"]["sha"]
        if not isinstance(tree_id, str):
            raise ValueError("Missing root tree")
        raw_tree = capture(
            output, "tree", ["gh", "api", base + "/git/trees/" + tree_id + "?recursive=1"]
        )
        tree = load_agent_json(raw_tree, max_bytes=4 * 1024**2)
        if tree.get("sha") != tree_id or tree.get("truncated") is not False:
            raise ValueError("Incomplete or wrong tree response")
        entries = tree.get("tree")
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            raise ValueError("Invalid recursive tree")
        if any(
            (e.get("type"), e.get("mode"))
            not in {("tree", "040000"), ("blob", "100644"), ("blob", "100755")}
            for e in entries
        ):
            raise ValueError("Unsupported link/submodule/Git mode; no source acquisition")
        blobs = [e for e in entries if e["type"] == "blob"]
        sizes = [e.get("size") for e in blobs]
        if any(type(s) is not int or s < 0 or s > 16 * 1024**2 for s in sizes):
            raise ValueError("Invalid or oversized blob")
        total = sum(sizes)
        if not 1 <= len(blobs) <= 1000 or total > 32 * 1024**2:
            raise ValueError("Tree exceeds unchanged intake limits")
        cache = output / "cache"
        cache.mkdir()
        atomic_write_bytes(cache / "tree-exact.json", raw_tree)
        # Adapt the Git API layout to the existing exact-OID recovery helper. The original
        # API bytes remain retained; the helper does not trust GitHub's signature verdict.
        try:
            raw_commit = recover_github_commit(
                json_bytes(
                    {
                        "sha": candidate.revision,
                        "commit": {"verification": commit.get("verification")},
                    }
                ),
                revision=candidate.revision,
            )
        except GitVerificationError:
            bare = output / "commit-objects.git"
            capture(output, "git-init", ["git", "init", "--bare", "--template=", str(bare)])
            git = [
                "git",
                "--git-dir=" + str(bare),
                "-c",
                "core.hooksPath=" + str(output / "no-hooks"),
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "fetch.fsckObjects=true",
            ]
            capture(
                output,
                "git-fetch",
                [
                    *git,
                    "fetch",
                    "--no-tags",
                    "--depth=1",
                    "--filter=blob:none",
                    candidate.url + ".git",
                    candidate.revision,
                ],
            )
            raw_commit = capture(
                output,
                "git-commit",
                [*git, "cat-file", "commit", candidate.revision],
                limit=1024**2,
            )
        if git_object_oid("commit", raw_commit) != candidate.revision:
            raise ValueError("Raw commit hash differs")
        atomic_write_bytes(cache / "commit.bin", raw_commit)
        archive = capture(
            output,
            "archive",
            ["gh", "api", base + "/zipball/" + candidate.revision],
            limit=16 * 1024**2,
        )
        atomic_write_bytes(cache / "source.zip", archive)
        spec = RepositoryIntakeSpec(
            source_label=candidate.url,
            revision=candidate.revision,
            root_tree=tree_id,
            archive_sha256=sha256_file(cache / "source.zip"),
            raw_commit_sha256=sha256_file(cache / "commit.bin"),
            tree_response_sha256=sha256_file(cache / "tree-exact.json"),
            expected_files=len(blobs),
            expected_bytes=total,
            license_status="unknown",
            role="formative-pilot",
        )
        atomic_write_model(output / "intake-spec.json", spec)
        prepare_repository(spec, cache=cache, output=output / "prepared")
        preview = build_preview(candidate, spec, output / "prepared")
        write_preview(preview, output / "preflight")
        verify_preview(output / "preflight", candidate, spec, output / "prepared")
        state = "prepared-previewed-not-admitted"
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        atomic_write_bytes(
            output / "status.json",
            json_bytes(
                {
                    "state": state,
                    "error": error,
                    "candidate": candidate.candidate_id,
                    "scanner_invocations": 0,
                    "findings": None,
                    "target_code_executed": False,
                    "scanning_authorization": "not-granted",
                }
            ),
        )
        paths = [p for p in sorted(output.rglob("*")) if p.is_file()]
        atomic_write_bytes(
            output / "acquisition-manifest.json",
            json_bytes(
                {
                    "contract": "corpus-acquisition-manifest-v1",
                    "files": [
                        {
                            "path": p.relative_to(output).as_posix(),
                            "sha256": sha256_file(p),
                            "bytes": p.stat().st_size,
                        }
                        for p in paths
                    ],
                }
            ),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = load_candidates(args.candidates)
    selected = [c for c in manifest.candidates if c.candidate_id == args.id]
    if len(selected) != 1:
        raise ValueError("Select one recorded candidate ID")
    acquire(selected[0], args.output.resolve())
    print("Prepared and previewed " + args.id + "; scanner invocations=0; admission pending")


if __name__ == "__main__":
    main()
