from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "tools" / "import_rule_drafts.py"
_SPEC = importlib.util.spec_from_file_location("rule_draft_import", _PATH)
assert _SPEC and _SPEC.loader
importer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(importer)


def fixture_plan(
    tmp_path: Path, body: bytes = b"raise RuntimeError('never execute')\r\n"
) -> tuple[Path, Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    raw = b"```python\r\n" + body + b"```\r\n"
    (source / "draft.md").write_bytes(raw)
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "contract": "rule-draft-extraction-plan-v1",
                "documents": [
                    {
                        "source": "draft.md",
                        "sha256": importer.digest(raw),
                        "outputs": [{"file": "draft.py.txt", "ranges": [[2, 2]]}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return plan, source, tmp_path / "payloads"


def test_preserves_bytes_and_never_executes(tmp_path: Path) -> None:
    body = b"\xc2\xa0\xc2\xa0raise RuntimeError('never execute')\r\n"
    plan, source, output = fixture_plan(tmp_path, body)
    importer.materialize(plan, source, output)
    assert (output / "draft.py.txt").read_bytes() == body
    importer.materialize(plan, source, output, verify=True)
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["records"][0]["inspection"]["nonbreaking_spaces"] == 2
    assert not manifest["scanner_execution"]


def test_refuses_source_change_before_writing(tmp_path: Path) -> None:
    plan, source, output = fixture_plan(tmp_path)
    (source / "draft.md").write_text("changed")
    with pytest.raises(ValueError, match="digest mismatch"):
        importer.materialize(plan, source, output)
    assert not output.exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"file": "../escape.py.txt"}, "leaf filename"),
        ({"file": "active.py"}, "inert"),
        ({"ranges": [[0, 2]]}, "line span"),
        ({"ranges": [[2, 99]]}, "line span"),
        ({"ranges": [[2, 2], [2, 2]]}, "line span"),
        ({"ranges": [[1, 2]]}, "Markdown fence"),
        ({"ranges": []}, "Empty extraction"),
    ],
)
def test_refuses_invalid_output_plan(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    plan, source, output = fixture_plan(tmp_path)
    data = json.loads(plan.read_text())
    data["documents"][0]["outputs"][0].update(change)
    plan.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=message):
        importer.materialize(plan, source, output)
    assert not output.exists()


def test_never_overwrites_and_detects_modified_payload(tmp_path: Path) -> None:
    plan, source, output = fixture_plan(tmp_path)
    importer.materialize(plan, source, output)
    with pytest.raises(FileExistsError):
        importer.materialize(plan, source, output)
    (output / "draft.py.txt").write_text("changed")
    with pytest.raises(ValueError, match="Payload differs"):
        importer.materialize(plan, source, output, verify=True)


def test_replay_rejects_extra_files(tmp_path: Path) -> None:
    plan, source, output = fixture_plan(tmp_path)
    importer.materialize(plan, source, output)
    (output / "extra.txt").write_text("extra")
    with pytest.raises(ValueError, match="membership"):
        importer.materialize(plan, source, output, verify=True)


def test_lexical_counts_are_not_detector_claims() -> None:
    data = b"""class Category(Enum):
    ONE = "one"

def score():
    return {"id": "A2A-001"}
def score():
    return {"id": "A2A-001"}
"""
    result = importer.text_inventory(data)
    assert result["literal_id_entries"] == ["A2A-001", "A2A-001"]
    assert result["unique_literal_id_count"] == 1
    assert result["category_members"] == ["ONE"]
    assert result["duplicate_function_definitions"] == {"score": 2}


def test_joins_ordered_parts_without_altering_source(tmp_path: Path) -> None:
    plan, source, output = fixture_plan(tmp_path)
    raw = b"```python\none\n```\n\n```python\ntwo\n```\n"
    (source / "draft.md").write_bytes(raw)
    data = json.loads(plan.read_text())
    data["documents"][0]["sha256"] = importer.digest(raw)
    data["documents"][0]["outputs"][0]["ranges"] = [[2, 2], [6, 6]]
    plan.write_text(json.dumps(data))
    importer.materialize(plan, source, output)
    assert (output / "draft.py.txt").read_bytes() == b"one\ntwo\n"
