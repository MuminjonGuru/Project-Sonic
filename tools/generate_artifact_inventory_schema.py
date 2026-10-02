from pathlib import Path

from agentsec_evidence.agents.inventory import inventory_schema
from agentsec_evidence.core.io import atomic_write_bytes, json_bytes

root = Path(__file__).resolve().parents[1] / "schemas/artifact-inventory-v1"
atomic_write_bytes(root / "inventory.schema.json", json_bytes(inventory_schema()))
