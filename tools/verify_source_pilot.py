"""Replay the sealed pilot offline without running any scanner or target."""

import argparse
import json
from pathlib import Path

from agentsec_evidence.pilot.validation import validate_source_pilot

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("root", type=Path)
args = parser.parse_args()
print(json.dumps(validate_source_pilot(Path(__file__).resolve().parents[1], args.root), indent=2))
