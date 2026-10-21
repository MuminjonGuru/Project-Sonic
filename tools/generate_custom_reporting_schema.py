"""Generate the additive report schema without rewriting reporting-v1."""

import json
from pathlib import Path

from agentsec_evidence.reporting.custom_models import CustomCommonReport

root = Path(__file__).resolve().parents[1] / "schemas/reporting-v5"
root.mkdir(parents=True, exist_ok=True)
(root / "common-report.schema.json").write_text(
    json.dumps(CustomCommonReport.model_json_schema(), indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
