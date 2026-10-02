import json
import subprocess
import sys
from pathlib import Path

from agentsec_evidence.core.identity import sha256_file

ROOT = Path(__file__).resolve().parents[2]


def test_controlled_view_preparation_preserves_evidence_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    output = tmp_path / "views"
    argv = [
        sys.executable,
        str(ROOT / "tools/verify_input_views.py"),
        "--prepare-only",
        "--output",
        str(output),
    ]
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60, check=True)
    summary = json.loads(result.stdout)
    assert summary["cases"] == 4 and summary["preparations"] == 8
    assert summary["syntax_worker_invocations"] == summary["scanner_invocations"] == 0
    assert summary["target_code_executed"] is False and summary["repeated_semantics_equal"] is True
    assert all(row["input_gate_passed"] is None for row in summary["rows"])
    for record in json.loads((output / "evidence-manifest.json").read_bytes())["files"]:
        assert sha256_file(output / record["path"]) == record["sha256"]
    before = {p: sha256_file(p) for p in output.rglob("*") if p.is_file()}
    again = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60, check=False)
    assert again.returncode != 0
    assert before == {p: sha256_file(p) for p in output.rglob("*") if p.is_file()}
