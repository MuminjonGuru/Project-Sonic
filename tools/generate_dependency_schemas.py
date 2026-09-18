from pathlib import Path

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.models import DependencyScope, StageComparison, StageEvidence

root = Path(__file__).resolve().parents[1] / "schemas/dependency-v1"
root.mkdir(parents=True, exist_ok=True)
for name, model in (
    ("scope", DependencyScope),
    ("stage", StageEvidence),
    ("comparison", StageComparison),
):
    (root / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))
