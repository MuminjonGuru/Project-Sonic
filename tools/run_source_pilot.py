"""Run the approved fixed pilot with offline tools, without executing target code."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentsec_evidence.pilot.runner import run_source_pilot


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--rule-source", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker", type=Path)
    args = parser.parse_args()
    run_source_pilot(
        project=Path(__file__).resolve().parents[1],
        cache=args.cache,
        rule_source=args.rule_source,
        database=args.database,
        output=args.output,
        docker=args.docker,
    )


if __name__ == "__main__":
    main()
