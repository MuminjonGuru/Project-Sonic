from __future__ import annotations

from pathlib import Path

from agentsec_evidence.validation.checks import ProductSchema, validate_product_schemas


def test_schema_validation_rejects_duplicate_jsonl_keys(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    (bundle_root / "duplicate.jsonl").write_text(
        '{"schema_version":"0.1.0","schema_version":"0.1.0"}\n',
        encoding="utf-8",
    )

    report = validate_product_schemas(
        run_id="run_validation_test",
        bundle_root=bundle_root,
        schema_root=project_root / "schemas" / "v0.1.0",
        products=[ProductSchema("duplicate.jsonl", "finding.schema.json", json_lines=True)],
    )

    assert report.passed is False
    assert "Duplicate JSON key" in report.checks[0].detail
