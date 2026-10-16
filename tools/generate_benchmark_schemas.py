"""Regenerate the additive development benchmark-plan contracts."""

from pathlib import Path

from agentsec_evidence.benchmarks.attempt_models import (
    AttemptFinish,
    AttemptStart,
    AttemptStartV2,
    BenchmarkProgress,
    BenchmarkProgressV2,
    DependencyAttemptFinish,
    DependencyProgress,
    KicsAttemptFinish,
    KicsProgress,
    SemgrepAttemptFinish,
    SemgrepProgress,
)
from agentsec_evidence.benchmarks.models import (
    BenchmarkDryRun,
    BenchmarkDryRunV2,
    BenchmarkDryRunV3,
    BenchmarkPlan,
    BenchmarkPlanV2,
    DependencyBenchmarkPlan,
    DependencyPreview,
    KicsBenchmarkPlan,
    KicsPreview,
    SemgrepBenchmarkPlan,
    SemgrepPreview,
)
from agentsec_evidence.core.io import json_bytes


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas/benchmark-v1"
    root.mkdir(parents=True, exist_ok=True)
    for name, model in (
        ("plan", BenchmarkPlan),
        ("dry-run", BenchmarkDryRun),
        ("attempt-start", AttemptStart),
        ("attempt-finish", AttemptFinish),
        ("progress", BenchmarkProgress),
    ):
        (root / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))
    current = root.parent / "benchmark-v2"
    current.mkdir(exist_ok=True)
    (current / "dry-run.schema.json").write_bytes(json_bytes(BenchmarkDryRunV2.model_json_schema()))
    for name, model in (
        ("plan", BenchmarkPlanV2),
        ("attempt-start", AttemptStartV2),
        ("progress", BenchmarkProgressV2),
    ):
        (current / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))
    newest = root.parent / "benchmark-v3"
    newest.mkdir(exist_ok=True)
    (newest / "dry-run.schema.json").write_bytes(json_bytes(BenchmarkDryRunV3.model_json_schema()))
    semgrep = root.parent / "benchmark-semgrep-v1"
    semgrep.mkdir(exist_ok=True)
    for name, model in (
        ("plan", SemgrepBenchmarkPlan),
        ("dry-run", SemgrepPreview),
        ("attempt-finish", SemgrepAttemptFinish),
        ("progress", SemgrepProgress),
    ):
        (semgrep / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))
    kics = root.parent / "benchmark-kics-v1"
    kics.mkdir(exist_ok=True)
    for name, model in (
        ("plan", KicsBenchmarkPlan),
        ("dry-run", KicsPreview),
        ("attempt-finish", KicsAttemptFinish),
        ("progress", KicsProgress),
    ):
        (kics / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))
    dependency = root.parent / "benchmark-dependency-v1"
    dependency.mkdir(exist_ok=True)
    for name, model in (
        ("plan", DependencyBenchmarkPlan),
        ("dry-run", DependencyPreview),
        ("attempt-finish", DependencyAttemptFinish),
        ("progress", DependencyProgress),
    ):
        (dependency / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))


if __name__ == "__main__":
    main()
