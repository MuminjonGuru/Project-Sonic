"""Prepare the original fifteen controlled cases; no scanning, fetching or retry."""

import argparse
from pathlib import Path

from agentsec_evidence.benchmarks.research_plan import build_research_plan
from agentsec_evidence.benchmarks.service import plan_bytes
from agentsec_evidence.research.retained import plain_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--rule-source", required=True, help="Existing workspace-relative rules")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    workspace = plain_path(project / "workspace", directory=True)
    parent = plain_path(args.output.parent, directory=True)
    if not parent.is_relative_to(workspace) or args.output.suffix != ".json":
        raise ValueError("Output must be a new JSON file under the existing workspace")
    for directory in (parent, *parent.parents):
        if directory == workspace:
            break
        if any(
            (directory / name).exists()
            for name in (
                "evidence-manifest.json",
                "bundle-manifest.json",
                "report-manifest.json",
                "review-manifest.json",
                "validation.json",
            )
        ):
            raise ValueError("Do not add plans to finalized evidence or benchmark sessions")
    plan = build_research_plan(project, plan_id=args.plan_id, rule_source=args.rule_source)
    with (parent / args.output.name).open("xb") as stream:
        stream.write(plan_bytes(plan))
    print(str(parent / args.output.name))


if __name__ == "__main__":
    main()
