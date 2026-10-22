"""Prepare the fixed corpus offline; never approve admissions or launch scanners."""

import argparse
from pathlib import Path

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.corpus.contracts import dry_run, load_preparation, prepare_core
from agentsec_evidence.intake.corpus import load_candidates
from agentsec_evidence.intake.corpus_validation import REGISTRY
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.research.retained import plain_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--validations", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = plain_path(args.project, directory=True)
    output = args.output.absolute()
    plain_path(output.parent, directory=True)
    if output.exists() or not output.is_relative_to(project / "workspace"):
        raise ValueError("Use a new ignored corpus preparation folder")
    registry = load_candidates(project / REGISTRY)
    output.mkdir()
    rows = []
    try:
        for candidate in registry.candidates:
            root = output / candidate.candidate_id
            row = {"candidate_id": candidate.candidate_id, "state": "preparing"}
            rows.append(row)
            save(output / "cohort.json", {"finished": False, "rows": rows, "detectors_run": 0})
            prepare_core(project, args.validations / candidate.candidate_id, args.rules, root)
            plan = load_preparation(project, root)
            if plan.validation.preview.candidate != candidate:
                raise ValueError("Prepared candidate differs from frozen corpus")
            row.update(
                state="prepared",
                plan_sha256=sha256_file(root / "plan.json"),
                preparation_manifest_sha256=sha256_file(root / "evidence-manifest.json"),
                preview=dry_run(plan),
            )
            print(candidate.candidate_id + ": prepared; no scanner launch", flush=True)
    except BaseException as exc:
        save(
            output / "cohort.json",
            {
                "finished": False,
                "rows": rows,
                "detectors_run": 0,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            },
        )
        raise
    save(
        output / "cohort.json",
        {
            "finished": True,
            "rows": rows,
            "detectors_run": 0,
            "registry_sha256": sha256_file(project / REGISTRY),
        },
    )


if __name__ == "__main__":
    main()
