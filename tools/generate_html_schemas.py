from pathlib import Path

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.html import HtmlManifest


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas/offline-html-report-v1"
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.schema.json").write_bytes(json_bytes(HtmlManifest.model_json_schema()))


if __name__ == "__main__":
    main()
