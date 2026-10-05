import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentsec_evidence.research.models import load_research_profile
from agentsec_evidence.research.schema_export import schema_documents

ROOT = Path(__file__).resolve().parents[2]


def test_research_schemas_match_models() -> None:
    schemas = schema_documents()
    directory = ROOT / "schemas/semgrep-research-v1"
    assert {p.name for p in directory.glob("*.json")} == set(schemas)
    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        assert json.loads((directory / name).read_bytes()) == schema


def test_candidate_retains_all_68_without_research_admission() -> None:
    raw = (ROOT / "configs/research/semgrep-python-candidate-v1.json").read_bytes()
    profile = load_research_profile(raw)
    assert len(profile.rules) == 68
    assert sum(rule.upstream_test_state == "passed" for rule in profile.rules) == 64
    assert profile.public_source_admission == "not-granted"
    Draft202012Validator(schema_documents()["candidate-profile.schema.json"]).validate(
        json.loads(raw)
    )


def test_controlled_registry_is_development_not_target_execution() -> None:
    registry = json.loads(
        (ROOT / "test_cases/development/semgrep-research/cases.json").read_bytes()
    )
    profile = load_research_profile(
        (ROOT / "configs/research/semgrep-python-candidate-v1.json").read_bytes()
    )
    conditions = registry["conditions"]
    assert registry["target_execution"] is False
    assert registry["role"] == "development-not-held-out"
    assert len(conditions) == len({case["id"] for case in conditions}) == 30
    assert {case["rule_id"] for case in conditions}.issubset(
        {rule.native_rule_id for rule in profile.rules}
    )
    assert all(type(case["condition_present"]) is bool for case in conditions)
    assert len(registry["policy_case"]["files"]) == 12
