import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.intake.schema_export import schema_documents

ROOT = Path(__file__).resolve().parents[2]


def test_authored_git_plan_workflow_replays_and_preserves_evidence(tmp_path: Path) -> None:
    output = tmp_path / "git-verification"
    argv = [sys.executable, str(ROOT / "tools/verify_git_input_plan.py"), "--output", str(output)]
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=30, check=True)
    summary = json.loads(result.stdout)
    assert summary["files_verified"] == summary["files_accounted_for"] == 21
    assert summary["selected_files"] == 5 and summary["excluded_files"] == 16
    assert summary["repeated_bytes_equal"] is True
    assert summary["snapshot_copy_reverified"] is True
    assert summary["scanner_executed"] is summary["target_code_executed"] is False
    for name, schema in schema_documents().items():
        filename = "git-verification.json" if name.startswith("git-") else "input-plan.json"
        Draft202012Validator(schema).validate(json.loads((output / filename).read_bytes()))
    records = json.loads((output / "evidence-manifest.json").read_bytes())["files"]
    for record in records:
        path = output / record["path"]
        assert path.stat().st_size == record["bytes"]
        assert sha256_file(path) == record["sha256"]
    before = {p: sha256_file(p) for p in output.rglob("*") if p.is_file()}
    again = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert again.returncode != 0
    assert {p: sha256_file(p) for p in output.rglob("*") if p.is_file()} == before
