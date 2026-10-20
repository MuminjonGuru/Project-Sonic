"""Pin explicitly selected retained sessions; this does not run or admit scanners."""

import argparse
from pathlib import Path

from agentsec_evidence.benchmarks.service import load_plan
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.service import require_new_derivative
from agentsec_evidence.research.retained import plain_path
from agentsec_evidence.scoring.models import ScorePlan, SessionInput


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--session", action="append", required=True)
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--exclusion", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = plain_path(args.project_root, directory=True)
    workspace = plain_path(project / "workspace", directory=True)
    parent = plain_path(args.output.parent, directory=True)
    if not parent.is_relative_to(workspace) or args.output.suffix != ".json":
        raise ValueError("Output must be a new JSON file under the existing workspace")
    destination = require_new_derivative(parent / args.output.name, [])
    for directory in (parent, *parent.parents):
        if directory == workspace:
            break
        if any(
            (directory / name).exists()
            for name in ("scoring-manifest.json", "review-manifest.json", "validation.json")
        ):
            raise ValueError("Do not add plans to finalized evidence or sessions")
    inputs = []
    for identity in args.session:
        # Validate the hash-shaped identifier before constructing an input path.
        request = SessionInput(
            session=identity, plan_sha256="0" * 64, validation_sha256="0" * 64, role="development"
        )
        root = plain_path(project / "workspace/benchmarks" / request.session, directory=True)
        frozen = load_plan(root / "plan.json")
        inputs.append(
            SessionInput(
                session=identity,
                plan_sha256=sha256_file(root / "plan.json"),
                validation_sha256=sha256_file(root / "validation.json"),
                role="formative-pilot"
                if frozen.contract == "benchmark-public-pilot-plan-v1"
                else "development",
            )
        )
    plan = ScorePlan(
        sessions=tuple(inputs), selection_rationale=args.rationale, exclusions=tuple(args.exclusion)
    )
    with destination.open("xb") as handle:
        handle.write(json_bytes(plan.model_dump(mode="json")))


if __name__ == "__main__":
    main()
