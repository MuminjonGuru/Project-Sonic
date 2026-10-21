from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import network_data as detector
from agentsec_evidence.custom_rules.network_catalog import CATALOG_SHA256, RULES
from agentsec_evidence.custom_rules.network_data import NetworkFileResult, scan_source

CASES = json.loads(
    (Path(__file__).parents[2] / "test_cases/development/network-data-v1/cases.json").read_text(
        encoding="utf-8"
    )
)["cases"]


def scan(source: str) -> NetworkFileResult:
    return scan_source(source.encode(), path="network.py")


def ids(result: NetworkFileResult) -> list[str] | None:
    return None if result.findings is None else [item.rule_id for item in result.findings]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_development_expectations(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert ids(result) == case["rules"]
    assert sorted({item.rule_id for item in result.inventory if item.rule_id}) == case["inventory"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_registry_preserves_all_ids_without_claiming_eighteen_detectors() -> None:
    assert len(RULES) == len({rule.rule_id for rule in RULES}) == 18
    assert Counter(rule.status for rule in RULES) == {
        "active-condition": 10,
        "inventory-only": 3,
        "deferred": 5,
    }
    assert len(CATALOG_SHA256) == 64
    active = {rule.rule_id for rule in RULES if rule.status == "active-condition"}
    observed = {rule for case in CASES for rule in case["rules"] or []}
    assert observed == active
    assert all(rule.priority is None for rule in RULES if rule.status != "active-condition")


@pytest.mark.parametrize(
    "source",
    [
        "import requests as r\nr.get(url)",
        "from requests import get as fetch\nfetch(url)",
        "def f(url):\n    import httpx\n    return httpx.get(url)",
        "import requests\nclass C:\n    requests = other\n"
        "    def f(self, url):\n        return requests.get(url)",
    ],
)
def test_import_resolution(source: str) -> None:
    assert ids(scan(source)) == ["NET-DATA-001"]


@pytest.mark.parametrize(
    "source",
    [
        "import requests\ndef f(requests, url):\n    return requests.get(url)",
        "import requests\nrequests = other\nrequests.get(url)",
        "if flag:\n    import requests\nrequests.get(url)",
        "from something import *\nrequests.get(url)",
        "def print(x):\n    return x\nprint(secret)",
        "import os\ndef f(os):\n    return os.getenv('SPIFFE_ID')",
    ],
)
def test_shadowed_or_ambiguous_names_do_not_invent_binding(source: str) -> None:
    assert ids(scan(source)) == []


@pytest.mark.parametrize(
    "expression",
    [
        "f'https://example.test/{part}'",
        "f'https://example.test/?q={part}'",
        "'https://example.test/' + part",
    ],
)
def test_path_or_query_interpolation_is_not_authority_control(expression: str) -> None:
    assert ids(scan(f"import requests\nrequests.get({expression})")) == ["NET-DATA-001"]


@pytest.mark.parametrize(
    "expression",
    [
        "f'https://{host}/fixed'",
        "'https://' + host + '/fixed'",
        "f'https://fixed.test:{port}/fixed'",
    ],
)
def test_authority_condition_does_not_claim_hostname_only(expression: str) -> None:
    assert ids(scan(f"import requests\nrequests.get({expression})")) == [
        "NET-DATA-001",
        "NET-DATA-003",
    ]


def test_no_neighboring_url_or_comment_leakage() -> None:
    result = scan(
        "import requests\nrequests.get(url)\n# token=not_a_query\nrequests.get('https://fixed.test')"
    )
    assert ids(result) == ["NET-DATA-001"]
    assert result.findings and result.findings[0].location.start_line == 2


def test_native_evidence_does_not_copy_secret_values_or_identifiers() -> None:
    for case in CASES:
        if "DO_NOT_EXPORT_SECRET" in case["source"]:
            assert "DO_NOT_EXPORT_SECRET" not in scan(case["source"]).model_dump_json()
    result = scan("import requests\nrequests.get(f'https://fixed.test/{CUSTOM_SECRET_NAME}')")
    assert "CUSTOM_SECRET_NAME" not in result.model_dump_json()
    assert ids(result) == ["NET-DATA-001", "NET-DATA-002"]


def test_trusted_hostname_does_not_downgrade_credentials() -> None:
    findings = [
        scan(f"import requests\nrequests.get('https://{host}/?api_key=sentinel')").findings
        for host in ("api.openai.com", "api.openai.com.attacker.invalid", "example.test")
    ]
    assert all(items and items[0].rule_id == "NET-DATA-002" for items in findings)
    assert len({items[0].priority for items in findings if items}) == 1


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nrequests.get(*args)",
        "import requests\nrequests.get(url, **options)",
        "import requests\nrequests.get(url, url=other)",
        "import requests\nrequests.get()",
        "import httpx\nhttpx.get('https://fixed.test', proxies=other)",
        "import httpx\nhttpx.Client().get('https://fixed.test', verify=False)",
        "import urllib.request\n"
        "urllib.request.urlopen('https://fixed.test', params={'token': value})",
        "import aiohttp\naiohttp.ClientSession(verify=False)",
    ],
)
def test_unmodeled_arguments_explicit_not_reported_as_supported(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert result.limitations_observed
    assert not any(item.rule_id for item in result.inventory)


def test_httpx_stream_and_aiohttp_options_follow_distinct_apis() -> None:
    result = scan(
        "import httpx, aiohttp\n"
        "httpx.stream('GET', 'https://fixed.test')\n"
        "aiohttp.ClientSession().get('https://fixed.test', proxy=proxy_url)"
    )
    assert ids(result) == ["NET-DATA-109"]
    assert [item.rule_id for item in result.inventory if item.rule_id] == ["NET-DATA-004"]


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nclient = requests.Session()\nclient.get(url)",
        "import httpx\nclient: object = httpx.Client()\nclient.get(url)",
        "import boto3\nclient = boto3.client('s3')\nclient.put_object(Bucket=bucket, Key=key)",
    ],
)
def test_assigned_instances_are_not_silently_claimed_as_covered(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert any(item.kind == "untracked-instance" for item in result.limitations_observed)


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nf = lambda: requests.get(url)",
        "import requests\nvalues = [requests.get(x) for x in urls]",
    ],
)
def test_inner_scopes_explicitly_unsupported(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert result.limitations_observed[0].kind == "unsupported-scope"


def test_environment_read_is_syntactic_not_claimed_dataflow() -> None:
    result = scan(
        "import requests, os\n"
        "secret_value = os.getenv('SECRET')\n"
        "requests.get('https://fixed.test', params={'q': secret_value})"
    )
    assert ids(result) == []


@pytest.mark.parametrize("query", ["{**extra}", "{computed_key: value}"])
def test_unenumerated_query_keys_remain_explicitly_unknown(query: str) -> None:
    result = scan(f"import requests\nrequests.get('https://fixed.invalid', params={query})")
    assert ids(result) == []
    assert any(item.kind == "unresolved-query" for item in result.limitations_observed)


def test_literal_dns_repetition_is_not_interpolation() -> None:
    result = scan("import socket\nsocket.gethostbyname('fixed' * 2)")
    assert ids(result) == []


@pytest.mark.parametrize("call", ["logging.info(msg=password)", "logging.log(20, msg=token)"])
def test_keyword_logging_message(call: str) -> None:
    assert ids(scan(f"import logging\n{call}")) == ["NET-DATA-005"]


def test_duplicate_logging_message_not_assumed_valid() -> None:
    result = scan("import logging\nlogging.info('fixed', msg=password)")
    assert ids(result) == []
    assert result.limitations_observed


def test_explicit_none_query_is_not_unknown_dictionary() -> None:
    result = scan("import requests\nrequests.get('https://fixed.invalid', params=None)")
    assert ids(result) == [] and not result.limitations_observed


def test_s3_two_arguments_one_observation_with_both_evidence_kinds() -> None:
    result = scan("import boto3\nboto3.client('s3').put_object(Bucket=bucket, Key=key)")
    assert ids(result) == ["NET-DATA-103"]
    assert result.findings and result.findings[0].evidence_kinds == [
        "storage-bucket",
        "storage-key",
    ]


def test_parse_and_resource_failures_have_null_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    for data in (b"def invalid(:", b"\xff"):
        result = scan_source(data, path="bad.py")
        assert result.state == "malformed" and result.findings is None
    monkeypatch.setattr(detector, "MAX_AST_NODES", 3)
    assert scan("import requests\nrequests.get(url)").state == "failed"


def test_observation_budget_is_not_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("import requests\nrequests.get(url)\nrequests.get(other)")
    assert result.state == "failed" and result.findings is None


def test_size_extension_path_and_url_parse_guards() -> None:
    assert scan_source(b"x" * (MAX_INPUT_BYTES + 1), path="large.py").state == "failed"
    assert scan_source(b"{}", path="mcp.json").state == "unsupported"
    with pytest.raises(ValueError):
        scan_source(b"", path="../outside.py")
    result = scan("import requests\nrequests.get('https://[invalid')")
    assert result.limitations_observed and ids(result) == []


def test_repeatability_identity_and_utf8_locations() -> None:
    source = "import requests\nlabel = '\u00e9'; requests.get(\n    value\n)"
    result = scan(source)
    assert result.model_dump_json() == scan(source).model_dump_json()
    assert NetworkFileResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings
    assert result.findings[0].location.start_utf8_byte_column == len("label = '\u00e9'; ".encode())
    assert result.findings[0].location.end_line == 4
    changed = scan(source + "\n")
    assert changed.findings and changed.findings[0].record_id != result.findings[0].record_id


def test_no_target_execution_or_network_lookup(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = scan(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        "import requests\nrequests.get('http://does-not-exist.invalid/')"
    )
    assert ids(result) == [] and not marker.exists()
