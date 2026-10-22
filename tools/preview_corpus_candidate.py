"""Offline replay/preflight for one explicit candidate; no network or scanner launch."""

import argparse
from pathlib import Path

from agentsec_evidence.intake.corpus import (
    build_preview,
    load_candidates,
    verify_preview,
    write_preview,
)
from agentsec_evidence.intake.repository import load_intake_spec


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    selected = [c for c in load_candidates(args.candidates).candidates if c.candidate_id == args.id]
    if len(selected) != 1:
        raise ValueError("Select one recorded candidate ID")
    spec = load_intake_spec(args.spec)
    if args.action == "build":
        write_preview(build_preview(selected[0], spec, args.prepared), args.output)
    preview = verify_preview(args.output, selected[0], spec, args.prepared)
    print(preview.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
