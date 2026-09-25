from pathlib import Path

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.models import CommonReport, DependencySummary

root = Path(__file__).resolve().parents[1] / "schemas/reporting-v1"
root.mkdir(parents=True, exist_ok=True)
for name, model in (("common-report", CommonReport), ("dependency-summary", DependencySummary)):
    (root / f"{name}.schema.json").write_bytes(json_bytes(model.model_json_schema()))
