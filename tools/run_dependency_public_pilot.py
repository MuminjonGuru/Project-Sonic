"""Run the already-admitted source-only pilot, preserving each attempt separately."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.analysis import SEMANTIC_VERSION, dependency_semantic_hash
from agentsec_evidence.dependencies.models import DependencyScope, StageEvidence
from agentsec_evidence.dependencies.pipeline import run_dependency_scan, validate_dependency_bundle


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--prior-bundles", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = args.report_directory.resolve()
    if not report.is_relative_to(root / "workspace"):
        raise ValueError("Reports must stay inside the development workspace")
    report.mkdir(parents=True, exist_ok=False)
    admission_file = root / "test_cases/pilot/langgraph-cicd/admission.json"
    admission = json.loads(admission_file.read_bytes())
    (report / "plan.json").write_bytes(
        json_bytes(
            {
                "repeats": 3,
                "semantic_version": SEMANTIC_VERSION,
                "purpose": "engineering pilot; not held-out evaluation",
                "admission": admission,
                "order": "direct OSV, Syft, SBOM OSV; no warmups; host cache uncontrolled",
            }
        )
    )
    if args.prior_bundles:
        reanalysis: list[JsonValue] = []
        for bundle in sorted(args.prior_bundles.glob("dep-run-*")):
            validate_dependency_bundle(bundle)
            scope = DependencyScope.model_validate_json((bundle / "scope.json").read_bytes())
            stages = [
                StageEvidence.model_validate_json(path.read_bytes())
                for path in sorted((bundle / "normalized").glob("*.json"))
            ]
            previous = json.loads((bundle / "report.json").read_bytes())
            reanalysis.append(
                {
                    "bundle": str(bundle),
                    "original_semantic_sha256": previous["semantic_sha256"],
                    "reanalysis_semantic_version": SEMANTIC_VERSION,
                    "reanalysis_semantic_sha256": dependency_semantic_hash(stages, scope),
                }
            )
        (report / "prior-reanalysis.json").write_bytes(json_bytes(reanalysis))
    results: list[JsonValue] = []
    for index in range(3):
        result = run_dependency_scan(
            project_root=root,
            workspace_root=report / "evidence",
            source=args.source,
            label="github:langchain-samples/cicd-pipeline-example",
            revision=admission["revision"],
            database=args.database,
            database_sha256=admission["database_sha256"],
            split="pilot",
            admission_file=admission_file,
        )
        results.append(result)
        (report / "results.json").write_bytes(json_bytes(results))
        print(
            f"{index + 1}: {result['state']}; semantic={result.get('semantic_sha256')}", flush=True
        )
    hashes = {str(cast(dict[str, JsonValue], result).get("semantic_sha256")) for result in results}
    passed = len(hashes) == 1 and all(
        cast(dict[str, JsonValue], result)["state"] == "complete" for result in results
    )
    (report / "summary.json").write_bytes(
        json_bytes(
            {
                "passed": passed,
                "runs": 3,
                "semantic_version": SEMANTIC_VERSION,
                "semantic_sha256": cast(JsonValue, sorted(hashes)),
            }
        )
    )
    if not passed:
        raise SystemExit("Pilot incomplete or nonrepeatable; all attempts preserved")


if __name__ == "__main__":
    main()
