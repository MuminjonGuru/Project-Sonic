from pathlib import Path

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.scoring.models import Metric, ScoreManifest, ScorePlan, ScoreReport


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas/evidence-scoring-v1"
    root.mkdir(parents=True, exist_ok=True)
    for name, model in (
        ("plan", ScorePlan),
        ("metric", Metric),
        ("report", ScoreReport),
        ("manifest", ScoreManifest),
    ):
        (root / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))


if __name__ == "__main__":
    main()
