"""Create a new local development-plan file with current code hashes; never execute it."""

import argparse
from pathlib import Path

from agentsec_evidence.benchmarks.dependency_boundary_plan import build_dependency_boundary_plan
from agentsec_evidence.benchmarks.dependency_mutation_plan import build_dependency_mutation_plan
from agentsec_evidence.benchmarks.dependency_plan import build_dependency_plan
from agentsec_evidence.benchmarks.kics_plan import build_kics_plan
from agentsec_evidence.benchmarks.models import AdmittedPlan
from agentsec_evidence.benchmarks.semgrep_plan import build_semgrep_plan
from agentsec_evidence.benchmarks.service import build_development_plan, plan_bytes
from agentsec_evidence.research.retained import plain_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument(
        "--treatment",
        choices=[
            "agent",
            "semgrep-first-slice",
            "kics-g2",
            "dependency-paired",
            "dependency-mutations",
            "dependency-boundaries",
        ],
        default="agent",
    )
    parser.add_argument("--database", help="Frozen database path relative to project workspace")
    parser.add_argument("--case", action="append", required=True, dest="case_ids")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument(
        "--allow-prelaunch-retry",
        action="store_true",
        help="Freeze one explicit missing-Docker retry per cell; never automatic",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    # Restrict generated plans to a pre-existing private workspace, never tracked source/evidence.
    workspace = plain_path(project / "workspace", directory=True)
    parent = plain_path(args.output.parent, directory=True)
    if not parent.is_relative_to(workspace) or args.output.suffix != ".json":
        raise ValueError("Output must be a new JSON file under the existing project workspace")
    for directory in (parent, *parent.parents):
        if directory == workspace:
            break
        if any(
            (directory / name).exists()
            for name in (
                "bundle-manifest.json",
                "evidence-manifest.json",
                "report-manifest.json",
                "review-manifest.json",
            )
        ):
            raise ValueError("Output cannot be added to finalized evidence")
    if args.database is not None and args.treatment not in {
        "dependency-paired",
        "dependency-mutations",
        "dependency-boundaries",
    }:
        raise ValueError("Database input applies only to the dependency treatment")
    plan: AdmittedPlan
    if args.treatment in {"dependency-paired", "dependency-mutations", "dependency-boundaries"}:
        if args.allow_prelaunch_retry or args.database is None:
            raise ValueError("Dependency requires an explicit frozen database and no retry opt-in")
        builder = (
            build_dependency_boundary_plan
            if args.treatment == "dependency-boundaries"
            else build_dependency_mutation_plan
            if args.treatment == "dependency-mutations"
            else build_dependency_plan
        )
        plan = builder(
            project,
            plan_id=args.plan_id,
            case_ids=tuple(args.case_ids),
            database=args.database,
            repetitions=args.repetitions,
        )
    elif args.treatment == "kics-g2":
        if args.allow_prelaunch_retry:
            raise ValueError("KICS does not admit manual retries")
        plan = build_kics_plan(
            project,
            plan_id=args.plan_id,
            case_ids=tuple(args.case_ids),
            repetitions=args.repetitions,
        )
    elif args.treatment == "semgrep-first-slice":
        if args.case_ids != ["dev-semgrep-basic-v1"] or args.allow_prelaunch_retry:
            raise ValueError("Semgrep requires its one existing case and no retry opt-in")
        plan = build_semgrep_plan(project, plan_id=args.plan_id, repetitions=args.repetitions)
    else:
        plan = build_development_plan(
            project,
            plan_id=args.plan_id,
            case_ids=tuple(args.case_ids),
            repetitions=args.repetitions,
            allow_prelaunch_retry=args.allow_prelaunch_retry,
        )
    with (parent / args.output.name).open("xb") as stream:
        stream.write(plan_bytes(plan))
    print(str(parent / args.output.name))


if __name__ == "__main__":
    main()
