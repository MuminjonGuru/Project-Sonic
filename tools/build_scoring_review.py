"""Generate a local review guide from an existing validated scoring bundle; never scan."""

import argparse
from pathlib import Path

from agentsec_evidence.scoring.review_guide import write_review_guide


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        write_review_guide(args.project_root, args.bundle, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Review guide refused: {exc}\n")
    print("Review guide created; no scans, native replay or acceptance recorded.")


if __name__ == "__main__":
    main()
