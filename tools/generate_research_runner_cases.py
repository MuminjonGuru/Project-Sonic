"""Generate controlled Git evidence with Git plumbing, never the verifier under test."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "test_cases/development/research-runner"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object-store", type=Path, required=True)
    args = parser.parse_args()
    store = args.object_store.resolve()
    if not store.is_relative_to(ROOT / "workspace") or store.exists():
        raise ValueError("Object store must be a new ignored workspace child")
    store.mkdir(parents=True)
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Controlled Development Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Controlled Development Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2026-10-05T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-10-05T00:00:00+00:00",
        }
    )

    def git(*arguments: str, data: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", *arguments],
            cwd=store,
            env=environment,
            input=data,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout

    git("init", "--bare", "--object-format=sha1", ".")
    registry = json.loads((DIRECTORY / "scenarios.json").read_bytes())
    for case in registry["cases"]:
        files = case["files"]

        def tree(prefix: str, files: dict[str, str] = files) -> str:
            children = sorted(
                {p[len(prefix) :].split("/")[0] for p in files if p.startswith(prefix)}
            )
            rows = []
            for child in children:
                path = prefix + child
                if path in files:
                    oid = (
                        git("hash-object", "-w", "--stdin", data=files[path].encode())
                        .decode()
                        .strip()
                    )
                    mode, kind = "100644", "blob"
                else:
                    oid = tree(path + "/")
                    mode, kind = "040000", "tree"
                rows.append(f"{mode} {kind} {oid}\t{child}\0".encode())
            return git("mktree", "-z", data=b"".join(rows)).decode().strip()

        root = tree("")
        revision = (
            git("commit-tree", root, data=f"Controlled case: {case['id']}\n".encode())
            .decode()
            .strip()
        )
        entries = []
        for row in git("ls-tree", "-r", "-t", "-l", "-z", root).split(b"\0"):
            if not row:
                continue
            meta, path = row.decode().split("\t", 1)
            mode, kind, oid, size = meta.split()
            entry = {"path": path, "mode": mode, "type": kind, "sha": oid}
            if kind == "blob":
                entry["size"] = int(size)
            entries.append(entry)
        case["git"] = {
            "revision": revision,
            "raw_commit": git("cat-file", "commit", revision).decode(),
            "tree": {"sha": root, "truncated": False, "tree": entries},
        }
    (DIRECTORY / "cases.json").write_text(
        json.dumps(registry, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"Generated {len(registry['cases'])} fixed cases using Git object plumbing")


if __name__ == "__main__":
    main()
