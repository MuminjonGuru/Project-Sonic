import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentsec_evidence.agents.inventory import build_artifact_inventory, inventory_schema
from agentsec_evidence.intake.snapshot import create_snapshot

ROOT = Path(__file__).resolve().parents[2]


def test_inventory_schema_is_separate_current_and_valid(tmp_path: Path) -> None:
    schema = inventory_schema()
    Draft202012Validator.check_schema(schema)
    assert (
        json.loads((ROOT / "schemas/artifact-inventory-v1/inventory.schema.json").read_bytes())
        == schema
    )
    target = tmp_path / "authored"
    target.mkdir()
    (target / "agent.py").write_text("# Not executed\n", encoding="utf-8")
    snapshot = create_snapshot(target, tmp_path / "snapshots", source_label="test", revision="v1")
    report = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    Draft202012Validator(schema).validate(report.model_dump(mode="json"))
