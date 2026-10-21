from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import memory_state as detector
from agentsec_evidence.custom_rules.memory_catalog import CATALOG_SHA256, LEGACY_MARKERS, RULES
from agentsec_evidence.custom_rules.memory_state import MemoryFileResult, scan_source

CASES = json.loads(
    (Path(__file__).parents[2] / "test_cases/development/memory-state-v1/cases.json").read_bytes()
)["cases"]


def scan(source: str) -> MemoryFileResult:
    return scan_source(source.encode(), path="memory.py")


def ids(result: MemoryFileResult) -> list[str] | None:
    return None if result.findings is None else [item.rule_id for item in result.findings]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_development_case(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert ids(result) == case["rules"]
    assert sorted({item.rule_id for item in result.inventory if item.rule_id}) == case["inventory"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_catalog_preserves_definitions_not_score_claims() -> None:
    assert [rule.rule_id for rule in RULES] == [
        f"MEM-SEC-{n:03}" for n in (*range(1, 11), *range(101, 109))
    ]
    assert Counter(rule.status for rule in RULES) == {
        "active-condition": 4,
        "inventory-only": 11,
        "deferred": 3,
    }
    assert len(CATALOG_SHA256) == 64
    assert set(LEGACY_MARKERS) == {"MEM-SEC-099", "MEM-SEC-MCP-001"}
    assert {item for case in CASES for item in case["rules"] or []} == {
        rule.rule_id for rule in RULES if rule.status == "active-condition"
    }
    assert {item for case in CASES for item in case["inventory"]} == {
        rule.rule_id for rule in RULES if rule.status == "inventory-only"
    }


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as b\nb.exec(memory)",
        "from builtins import eval as evaluate\nevaluate(memory)",
        "def f(memory):\n    return eval(memory)",
        "class C:\n    eval = other\n    def f(self, memory):\n        return eval(memory)",
        "eval(memory['code'])",
        "eval(memory.content)",
        "eval(f'prefix {history}')",
        "eval(context + suffix)",
    ],
)
def test_direct_memory_expressions(source: str) -> None:
    assert ids(scan(source)) == ["MEM-SEC-103"]


@pytest.mark.parametrize(
    "source",
    [
        "eval = other\neval(memory)",
        "from custom import eval\neval(memory)",
        "from .custom import eval\neval(memory)",
        "from custom import *\neval(memory)",
        "def f(eval):\n    return eval(memory)",
        "import json\njson = other\njson.dumps(secret)",
        "if ready:\n    import json\njson.dumps(secret)",
        "exec(value[memory])",
        "eval('memory')",
        "eval(next_value if memory else alternate)",
        "eval(extract(memory))",
    ],
)
def test_no_invented_api_or_value_flow(source: str) -> None:
    assert ids(scan(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        "import json as j\nj.dumps({'secret': token})",
        "from json import dumps as encode\nencode(obj=password)",
        "import pickle\npickle.dump(credentials, output)",
        "import yaml\nyaml.safe_dump(data=api_key)",
    ],
)
def test_credential_name_serialization(source: str) -> None:
    assert ids(scan(source)) == ["MEM-SEC-004"]


@pytest.mark.parametrize(
    "source",
    [
        "import json\njson.dumps({'token': 'example'})",
        "import json\njson.dumps({'context': 'ordinary text'})",
        "import json\njson.dumps(key)",
        "import json\njson.dumps(mask(secret))",
        "import json\njson.dumps(value if secret else alternate)",
        "import pickle\npickle.loads(memory)",
    ],
)
def test_no_literal_secret_or_unpickling_claim(source: str) -> None:
    assert ids(scan(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        "import json\njson.dump(memory)",
        "import json\njson.dumps(memory, obj=other)",
        "import json\njson.dumps(obj=secret, obj=other)",
        "import pickle\npickle.dump(memory)",
        "import yaml\nyaml.dump(data=secret, typo=True)",
        "exec(memory, source=other)",
        "exec(memory, invalid=True)",
        "eval(*values)",
        "print(memory, typo=True)",
        "import logging\nlogging.info(memory, msg=other)",
        "import logging\nlogging.log(memory, level=20)",
        "import requests\nrequests.post(url, memory, data=other)",
        "import httpx\nhttpx.post(url, memory)",
        "from langchain_core.messages import SystemMessage\nSystemMessage(memory, content=other)",
        "from langchain_core.messages import SystemMessage\nSystemMessage(memory, type='human')",
        "import httpx\nhttpx.post(url, json=memory, allow_redirects=True)",
        "import requests\nrequests.post(url, json=memory, follow_redirects=True)",
        "import yaml\nyaml.safe_dump(secret, Dumper=Custom)",
    ],
)
def test_unsupported_call_shapes_explicit(source: str) -> None:
    result = scan(source)
    assert ids(result) == [] and result.limitations_observed


@pytest.mark.parametrize(
    "source",
    [
        "print(memory)",
        "print(f'History: {history}')",
        "import logging\nlogging.info('History: %s', memory)",
        "import logging\nlogging.log(20, memory)",
        "import logging\nlogging.log(level=20, msg=memory)",
        "from requests import post as send\nsend(url, json=history)",
        "import requests\nrequests.post(url, memory)",
        "import requests\nrequests.request('POST', url, data=memory)",
        "import httpx\nhttpx.request('POST', url, json=memory)",
    ],
)
def test_direct_output_body_conditions(source: str) -> None:
    assert ids(scan(source)) == ["MEM-SEC-104"]


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nrequests.post(url, headers=memory)",
        "import requests\nrequests.post(memory, json='literal')",
        "import requests\nrequests.post(url, json=redact(memory))",
        "import httpx\nclient = httpx.Client()\nclient.post(url, json=memory)",
        "logger.info(memory)",
        "send(memory)",
        "publish(memory)",
        "print('memory')",
    ],
)
def test_headers_destinations_or_custom_sinks_not_body_claim(source: str) -> None:
    assert ids(scan(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        "{'role':'system', 'content':user_input}",
        "{'role':'system', 'content':f'Rules: {value}'}",
        "from langchain.messages import SystemMessage as S\nS(user_input)",
        "from langchain_core.messages.system import SystemMessage\nSystemMessage(content=value)",
    ],
)
def test_system_declaration_with_nonliteral_content(source: str) -> None:
    assert ids(scan(source)) == ["MEM-SEC-107"]


@pytest.mark.parametrize(
    "source",
    [
        "{'role':'system', 'content':'fixed'}",
        "{'role':'system', 'content':f'fixed'}",
        "{'role':'user', 'content':user_input}",
        "{'role':'system', 'content':value, 'role':'user'}",
        "{'role':'system', 'content':value, 'content':'fixed'}",
        "{'role':'system', 'content':value, **extra}",
        "{'role':dynamic_role, 'content':value}",
        "from langchain_core.messages import SystemMessage\nSystemMessage(content=['fixed'])",
        "from langchain_core.messages import SystemMessage\nSystemMessage(content_blocks=blocks)",
    ],
)
def test_message_near_misses_and_unknowns(source: str) -> None:
    assert ids(scan(source)) == []


def test_ordinary_features_are_inventory_not_security_scores() -> None:
    result = scan(
        "session_id = current\nself.memory = messages\n"
        "memory_version = 1\nsummary = summarize_history(messages, max_tokens=100)\n"
        "recent = messages[:20]\n"
    )
    assert ids(result) == []
    assert {"MEM-SEC-101", "MEM-SEC-102", "MEM-SEC-105", "MEM-SEC-106", "MEM-SEC-108"} <= {
        item.rule_id for item in result.inventory
    }
    assert "risk_score" not in result.model_dump_json()
    assert "confidence" not in result.model_dump_json()


@pytest.mark.parametrize("name", ["langchain", "langchain_core", "langgraph", "langchain_classic"])
def test_framework_inventory_is_import_not_comment(name: str) -> None:
    assert [item.rule_id for item in scan(f"import {name}").inventory] == ["MEM-SEC-005"]
    assert not scan(f"# import {name}\ntext = '{name}'").inventory


def test_relative_or_similarly_named_import_is_not_framework() -> None:
    assert not scan("from .langchain import Memory\nimport langchain_fake").inventory


def test_no_source_values_in_report_and_no_code_executed(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = scan(
        f"open({str(marker)!r}, 'w').write('DO_NOT_EXECUTE')\n"
        "import json\njson.dumps(CUSTOM_SECRET_VALUE)\n"
        "message={'role':'system', 'content':PRIVATE_CONTENT}\n"
    )
    assert not marker.exists()
    payload = result.model_dump_json()
    assert all(
        value not in payload
        for value in ("DO_NOT_EXECUTE", "CUSTOM_SECRET_VALUE", "PRIVATE_CONTENT", str(marker))
    )
    assert ids(result) == ["MEM-SEC-004", "MEM-SEC-107"]


@pytest.mark.parametrize(
    "source",
    [
        "print(mask(memory))",
        "import json\njson.dumps({**unknown})",
        "handler = lambda memory: eval(memory)",
        "[eval(memory) for memory in values]",
    ],
)
def test_unknown_transformations_and_scopes_not_clean_coverage(source: str) -> None:
    result = scan(source)
    assert ids(result) == [] and result.limitations_observed


def test_source_bound_stable_ids_and_utf8_locations() -> None:
    source = "label='\u00e9'; eval(\n memory\n)"
    result = scan(source)
    assert result.model_dump_json() == scan(source).model_dump_json()
    assert MemoryFileResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings and result.findings[0].location.end_line == 3
    assert result.findings[0].location.start_utf8_byte_column == len("label='\u00e9'; ".encode())
    changed = scan(source + "\n")
    assert changed.findings and result.findings[0].record_id != changed.findings[0].record_id


def test_guards_and_null_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    for data in (b"def broken(:", b"\xff"):
        result = scan_source(data, path="broken.py")
        assert result.state == "malformed" and result.findings is None
    result = scan_source(b"{}", path="state.json")
    assert result.state == "unsupported" and result.findings is None
    assert scan_source(b"x" * (MAX_INPUT_BYTES + 1), path="large.py").state == "failed"
    with pytest.raises(ValueError):
        scan_source(b"", path="../escape.py")
    monkeypatch.setattr(detector, "MAX_AST_NODES", 3)
    assert scan("eval(memory)").state == "failed"


def test_record_budget_not_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("eval(memory)\nexec(memory)")
    assert result.state == "failed" and result.findings is None


def test_known_value_does_not_hide_opaque_sibling() -> None:
    result = scan("import json\njson.dumps([memory, transform(other)])")
    assert result.limitations_observed
    assert any(item.rule_id == "MEM-SEC-010" for item in result.inventory)


def test_unsupported_body_fields_are_explicit_not_silently_clean() -> None:
    result = scan("import httpx\nhttpx.post(url, content=memory)")
    assert ids(result) == []
    assert any(item.kind == "unsupported-body-field" for item in result.limitations_observed)
