"""Generate additive core plan and admission schemas."""

from pathlib import Path

from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.corpus.contracts import CorpusCoreAdmission, CorpusCorePlan


def main() -> None:
    output = Path(__file__).resolve().parents[1] / "schemas/corpus-core-v1"
    for model, name in ((CorpusCorePlan, "plan"), (CorpusCoreAdmission, "admission")):
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"urn:agentsec-evidence:schema:corpus-core-{name}-v1"
        atomic_write_bytes(output / f"{name}.schema.json", json_bytes(schema))


if __name__ == "__main__":
    main()
