import json
import subprocess
import sys
from pathlib import Path

from agentsec_evidence.core.identity import sha256_file

ROOT = Path(__file__).resolve().parents[2]


def test_authored_helper_emits_verified_evidence_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "authored-inventory"
    argv = [
        sys.executable,
        str(ROOT / "tools/verify_artifact_inventory.py"),
        "--output",
        str(output),
    ]
    completed = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=30, check=True)
    summary = json.loads(completed.stdout)
    assert summary["files_retained"] == 19
    assert summary["files_with_candidates"] == 13
    assert summary["unclassified_files"] == 6
    assert summary["finding_count"] is None
    assert summary["repeat_bytes_equal"] is True
    manifest = json.loads((output / "evidence-manifest.json").read_bytes())
    for record in manifest["files"]:
        path = output / record["path"]
        assert sha256_file(path) == record["sha256"]
        assert path.stat().st_size == record["byte_length"]
    before = {p: sha256_file(p) for p in output.rglob("*") if p.is_file()}
    again = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert again.returncode != 0
    assert {p: sha256_file(p) for p in output.rglob("*") if p.is_file()} == before
