from pathlib import Path

from agentsec_evidence.models.schema_export import write_schemas


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    write_schemas(root / "schemas" / "v0.1.0")


if __name__ == "__main__":
    main()
