"""Generate additive repository-intake schemas from their Pydantic contracts."""

from pathlib import Path

from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.intake.repository import RepositoryIntakeReceipt, RepositoryIntakeSpec


def main() -> None:
    output = Path(__file__).resolve().parents[1] / "schemas/repository-intake-v1"
    for model, name in ((RepositoryIntakeSpec, "spec"), (RepositoryIntakeReceipt, "receipt")):
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"urn:agentsec-evidence:schema:repository-intake-{name}-v1"
        atomic_write_bytes(output / f"{name}.schema.json", json_bytes(schema))


if __name__ == "__main__":
    main()
