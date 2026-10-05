"""Re-verify the fixed cached pilot's source evidence; do not scan or execute the target."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec_evidence.intake.source_preparation import SourcePreparationSpec, prepare_cached_source

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "test_cases/pilot/langgraph-cicd/source-preparation.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache", type=Path, required=True, help="Previously retained pilot inputs"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="New path in an existing directory"
    )
    args = parser.parse_args()
    spec = SourcePreparationSpec.model_validate_json(SPEC.read_bytes())
    summary = prepare_cached_source(spec, cache=args.cache, output=args.output)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
