"""Regenerate the finding-review data contracts from their Pydantic models."""

from pathlib import Path

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reviews.models import ReviewBatch, ReviewManifest, ReviewSidecar


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas" / "review-v1"
    root.mkdir(parents=True, exist_ok=True)
    for name, model in (
        ("review-batch", ReviewBatch),
        ("review-sidecar", ReviewSidecar),
        ("review-manifest", ReviewManifest),
    ):
        (root / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))


if __name__ == "__main__":
    main()
