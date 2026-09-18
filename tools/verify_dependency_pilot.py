"""Sequential development matrix. Does not admit or scan a public repository."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.analysis import fraction, package_set
from agentsec_evidence.dependencies.models import DependencyScope, StageEvidence
from agentsec_evidence.dependencies.mutations import Mutation
from agentsec_evidence.dependencies.pipeline import run_dependency_scan, validate_dependency_bundle


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--report-directory", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = args.report_directory.resolve()
    if not report.is_relative_to(root / "workspace"):
        raise ValueError("Report directory must be under the development workspace")
    report.mkdir(parents=True, exist_ok=False)
    expected_path = root / "test_cases/development/dependency-basic/expected.json"
    expected = json.loads(expected_path.read_bytes())
    if expected["review_status"] != "student-confirmed-finite-scope":
        raise ValueError("Reviewed finite oracle required")
    cases: list[tuple[str, Mutation | None, str]] = [
        ("dependency-basic", None, "complete"),
        ("dependency-basic", None, "complete"),
        ("dependency-basic", None, "complete"),
        ("dependency-clean", None, "complete"),
        ("dependency-empty", None, "partial"),
        ("dependency-unresolved", None, "partial"),
        ("dependency-malformed", None, "failed"),
        ("dependency-unsupported", None, "failed"),
        ("dependency-basic", "remove-component", "complete"),
        ("dependency-basic", "remove-purl", "partial"),
        ("dependency-basic", "change-version", "complete"),
    ]
    (report / "plan.json").write_bytes(
        json_bytes(
            {
                "purpose": "engineering compatibility; not a performance benchmark",
                "repeats": 3,
                "warmups": 0,
                "order": "direct OSV, Syft, SBOM OSV",
                "cache": "fresh disposable container each stage; host file cache uncontrolled",
                "cases": cast(JsonValue, [list(case) for case in cases]),
            }
        )
    )
    results: list[JsonValue] = []
    semantic: str | None = None
    failures: list[str] = []
    for index, (case, mutation, expected_state) in enumerate(cases):
        result = run_dependency_scan(
            project_root=root,
            workspace_root=report / "evidence",
            database=args.database,
            database_sha256=expected["database_sha256"],
            source=root / "test_cases/development" / case / "target",
            label="fixture:" + case,
            revision="fixture-v1",
            mutation=mutation,
        )
        bundle = Path(str(result["bundle_root"]))
        validate_dependency_bundle(bundle)
        errors: list[str] = []
        oracle_metrics: dict[str, JsonValue] = {}
        if result["state"] != expected_state:
            errors.append(f"Expected {expected_state}, got {result['state']}")
        if case == "dependency-basic" and mutation is None:
            value = str(result.get("semantic_sha256"))
            if semantic is not None and value != semantic:
                errors.append("Semantic repeat mismatch")
            semantic = value
            if result["state"] == "complete":
                scope = DependencyScope.model_validate_json((bundle / "scope.json").read_bytes())
                expected_packages = {tuple(item) for item in expected["eligible_packages"]}
                expected_matches = {tuple(item) for item in expected["expected_matches"]}
                for name in ("syft", "cyclonedx", "osv-direct", "osv-sbom"):
                    stage = StageEvidence.model_validate_json(
                        (bundle / f"normalized/{name}.json").read_bytes()
                    )
                    observed_packages = package_set(stage) - set(scope.separate_local)
                    if observed_packages != expected_packages:
                        errors.append(f"Package oracle mismatch at {name}")
                    if any(item.status != "identified" for item in stage.observations):
                        errors.append(f"Unresolved or unsupported observation at {name}")
                    metrics: dict[str, JsonValue] = {
                        "inventory_recall": fraction(
                            len(observed_packages & expected_packages), len(expected_packages)
                        ).model_dump(mode="json"),
                        "unexpected_identities": cast(
                            JsonValue, sorted(observed_packages - expected_packages)
                        ),
                    }
                    if name.startswith("osv"):
                        matches = {
                            (item.name, item.version, item.canonical_advisory)
                            for item in stage.matches
                            if (item.name, item.version) not in set(scope.separate_local)
                        }
                        if matches != expected_matches:
                            errors.append(f"Advisory oracle mismatch at {name}")
                        metrics["match_precision"] = fraction(
                            len(matches & expected_matches), len(matches)
                        ).model_dump(mode="json")
                        metrics["match_recall"] = fraction(
                            len(matches & expected_matches), len(expected_matches)
                        ).model_dump(mode="json")
                    oracle_metrics[name] = metrics
        if case == "dependency-clean" and result["state"] == "complete":
            for name in ("osv-direct", "osv-sbom"):
                stage = StageEvidence.model_validate_json(
                    (bundle / f"normalized/{name}.json").read_bytes()
                )
                if package_set(stage) != {("requests", "2.33.0")} or stage.matches:
                    errors.append(f"Unaffected-version oracle mismatch at {name}")
        if mutation:
            comparisons = json.loads((bundle / "comparisons.json").read_bytes())
            handoff = next(
                item
                for item in comparisons
                if item["left"] == "syft" and item["right"] == "cyclonedx"
            )
            if ["requests", "2.31.0"] not in handoff["missing"]:
                errors.append("Injected export-boundary identity discrepancy not detected")
            if mutation == "remove-purl" and not handoff["missing_identifiers"]:
                errors.append("Missing purl not explained")
            observed = StageEvidence.model_validate_json(
                (bundle / "normalized/osv-sbom.json").read_bytes()
            )
            if mutation == "change-version":
                actual = {
                    (item.name, item.version, item.canonical_advisory) for item in observed.matches
                }
                if actual != {("requests", "2.32.5", "CVE-2026-25645")}:
                    errors.append("Consistent version mutation did not change matches as expected")
            elif any(
                item.name == "requests" and item.version == "2.31.0" for item in observed.matches
            ):
                errors.append("Removed matching identity still produced an advisory match")
        results.append(
            {
                "index": index,
                "case": case,
                "mutation": mutation,
                "state": result["state"],
                "bundle": str(bundle),
                "semantic_sha256": result.get("semantic_sha256"),
                "assertion_errors": cast(JsonValue, errors),
                "finite_oracle_metrics": oracle_metrics,
            }
        )
        failures.extend(f"{index}: {error}" for error in errors)
        (report / "results.json").write_bytes(json_bytes(results))
        print(
            f"{index}: {case} {mutation or 'baseline'} -> {result['state']}; "
            f"assertions={len(errors)}",
            flush=True,
        )
    (report / "summary.json").write_bytes(
        json_bytes(
            {
                "passed": not failures,
                "attempts": len(results),
                "baseline_semantic_sha256": semantic,
                "failures": cast(JsonValue, failures),
                "oracle": str(expected_path),
            }
        )
    )
    if failures:
        raise SystemExit("Development matrix has failed assertions; inspect preserved evidence")


if __name__ == "__main__":
    main()
