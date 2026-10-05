from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Literal

import pytest

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    SemgrepDualView,
    SemgrepPassEvidence,
    SemgrepResearchProfile,
    SemgrepResearchScope,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

ROOT = Path(__file__).resolve().parents[2]
PROFILE = (ROOT / "configs/research/semgrep-python-candidate-v1.json").read_bytes()
RULE = "python_eval_rule-eval"


def encoded(value: Any) -> bytes:
    return json.dumps(value).encode()


def scope() -> SemgrepResearchScope:
    return SemgrepResearchScope.model_validate(
        {
            "target_snapshot_id": "authored-test-not-git-attestation",
            "selection_sha256": "a" * 64,
            "profile_sha256": sha256_bytes(PROFILE),
            "selected_files": [
                {"path": name, "sha256": "b" * 64, "byte_length": 10, "media_type": "text/x-python"}
                for name in ("active.py", "excluded.py", "inline.py")
            ],
            "policy_files": [
                {
                    "path": ".semgrepignore",
                    "sha256": "c" * 64,
                    "byte_length": 8,
                    "media_type": "text/plain",
                }
            ],
        }
    )


def reports(*, policy: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    paths = ["active.py", "inline.py"] if policy else ["active.py", "excluded.py", "inline.py"]
    results = [
        {
            "check_id": RULE,
            "path": f"/src/{name}",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 10},
            "extra": {"message": "Eval condition", "severity": "WARNING"},
        }
        for name in paths
        if not (policy and name == "inline.py")
    ]
    native: dict[str, Any] = {
        "version": "1.174.0",
        "results": results,
        "errors": [],
        "skipped_rules": [],
        "paths": {"scanned": [f"/src/{name}" for name in paths], "skipped": []},
    }
    if policy:
        native["paths"]["skipped"] = [
            {"path": "/src/excluded.py", "reason": "semgrepignore_patterns_match"}
        ]
    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "semanticVersion": "1.174.0",
                        "rules": [{"id": RULE}],
                    }
                },
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
                "results": [
                    {
                        "ruleId": RULE,
                        "ruleIndex": 0,
                        "message": {"text": "Eval condition"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"/src/{name}",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {
                                        "startLine": 1,
                                        "startColumn": 1,
                                        "endLine": 1,
                                        "endColumn": 10,
                                    },
                                }
                            }
                        ],
                        **({"suppressions": [{"kind": "inSource"}]} if name == "inline.py" else {}),
                    }
                    for name in paths
                ],
            }
        ],
    }
    return native, sarif


def reconcile(
    native: dict[str, Any],
    sarif: dict[str, Any],
    *,
    role: Literal["research", "repository-policy"] = "research",
) -> SemgrepPassEvidence:
    return reconcile_semgrep_pass(
        profile_bytes=PROFILE,
        scope=scope(),
        execution_id=f"test-{role}",
        role=role,
        native_json=encoded(native),
        native_sarif=encoded(sarif),
    )


def test_dual_view_keeps_native_suppression_and_exclusion_distinct() -> None:
    research = reconcile(*reports())
    policy = reconcile(*reports(policy=True), role="repository-policy")
    view = build_dual_view(research, policy)
    assert [item.state for item in view.findings] == [
        "reported",
        "file-excluded",
        "native-suppression-marked",
    ]
    suppressed = policy.findings[-1]
    assert suppressed.json_pointer is None
    assert suppressed.model_dump(mode="json")["native_suppressions"] == [{"kind": "inSource"}]
    assert suppressed.review_state == "unreviewed"
    assert view.vulnerability_total is None
    assert view.analysis_completeness == "not-established"
    assert research.native_json_sha256 == sha256_bytes(encoded(reports()[0]))


def test_missing_policy_is_unknown_not_zero() -> None:
    view = build_dual_view(reconcile(*reports()))
    assert view.policy_state == "not-run"
    assert all(row.state == "unknown" and row.policy_index is None for row in view.findings)


def test_native_partial_file_retains_findings_and_error_reason() -> None:
    native, sarif = reports()
    native["paths"]["skipped"] = [
        {"path": "/src/active.py", "reason": "analysis_failed_parser_or_internal_error"}
    ]
    native["errors"] = [{"code": 2, "message": "unknown suppression rule"}]
    evidence = reconcile(native, sarif)
    assert evidence.files[0].state == "reported-with-native-issue"
    assert evidence.files[0].native_reason == "analysis_failed_parser_or_internal_error"
    assert len(evidence.findings) == 3
    assert len(evidence.native_errors) == 1


def test_policy_only_finding_is_not_silently_discarded() -> None:
    native, sarif = reports()
    native["results"].pop(0)
    sarif["runs"][0]["results"].pop(0)
    research = reconcile(native, sarif)
    with pytest.raises(ValueError, match="absent from evidence-retaining"):
        build_dual_view(research, reconcile(*reports(policy=True), role="repository-policy"))


def test_native_rejected_suppression_is_preserved_not_marked_accepted() -> None:
    native, sarif = reports(policy=True)
    sarif["runs"][0]["results"][-1]["suppressions"][0]["status"] = "rejected"
    evidence = reconcile(native, sarif, role="repository-policy")
    assert evidence.findings[-1].model_dump(mode="json")["native_suppressions"] == [
        {"kind": "inSource", "status": "rejected"}
    ]
    assert evidence.findings[-1].review_state == "unreviewed"


@pytest.mark.parametrize("reason", ["too_big", "analysis_failed", "future-native-reason"])
def test_non_policy_skip_is_not_an_exclusion(reason: str) -> None:
    native, sarif = reports(policy=True)
    native["paths"]["skipped"][0]["reason"] = reason
    view = build_dual_view(
        reconcile(*reports()), reconcile(native, sarif, role="repository-policy")
    )
    assert view.findings[1].state == "unknown"


@pytest.mark.parametrize(
    "gap",
    [
        "unreported",
        "native-error",
        "skipped-rule",
        "notification",
        "no-invocation",
        "unsuccessful",
        "not-observed",
    ],
)
def test_absent_policy_finding_does_not_become_fixed(gap: str) -> None:
    native, sarif = reports()
    native["results"].pop(1)
    sarif["runs"][0]["results"].pop(1)
    if gap == "unreported":
        native["paths"]["scanned"].remove("/src/excluded.py")
    elif gap == "native-error":
        native["errors"] = [{"message": "parse failure"}]
    elif gap == "skipped-rule":
        native["skipped_rules"] = [RULE]
    elif gap == "notification":
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
            {"message": {"text": "partial"}}
        ]
    elif gap == "no-invocation":
        sarif["runs"][0].pop("invocations")
    elif gap == "unsuccessful":
        sarif["runs"][0]["invocations"][0]["executionSuccessful"] = False
    view = build_dual_view(
        reconcile(*reports()), reconcile(native, sarif, role="repository-policy")
    )
    assert view.findings[1].state == ("not-observed" if gap == "not-observed" else "unknown")


@pytest.mark.parametrize(
    "mutation",
    [
        "version",
        "producer",
        "declarations",
        "duplicate-json",
        "duplicate-sarif",
        "json-only",
        "sarif-only",
        "message",
        "foreign-path",
        "scanned-duplicate",
        "skip-contradiction",
        "unknown-skip",
        "bad-suppression",
        "bad-status",
        "bad-base",
        "bool-rule-index",
        "bad-region",
        "multiple-runs",
        "multiple-invocations",
        "bad-success",
    ],
)
def test_native_conflicts_and_malformed_evidence_are_rejected(mutation: str) -> None:
    native, sarif = reports()
    run = sarif["runs"][0]
    result = run["results"][0]
    if mutation == "version":
        native["version"] = "future"
    elif mutation == "producer":
        run["tool"]["driver"]["name"] = []
    elif mutation == "declarations":
        run["tool"]["driver"]["rules"].append({"id": "unadmitted"})
    elif mutation == "duplicate-json":
        native["results"].append(copy.deepcopy(native["results"][0]))
    elif mutation == "duplicate-sarif":
        run["results"].append(copy.deepcopy(result))
    elif mutation == "json-only":
        run["results"].pop(0)
    elif mutation == "sarif-only":
        native["results"].pop(0)
    elif mutation == "message":
        result["message"]["text"] = "different"
    elif mutation == "foreign-path":
        native["paths"]["scanned"].append("foreign.py")
    elif mutation == "scanned-duplicate":
        native["paths"]["scanned"].append("/src/active.py")
    elif mutation in {"skip-contradiction", "unknown-skip"}:
        native["paths"]["skipped"] = [
            {
                "path": "active.py" if mutation == "skip-contradiction" else "outside.py",
                "reason": "semgrepignore_patterns_match",
            }
        ]
    elif mutation == "bad-suppression":
        result["suppressions"] = [{"kind": []}]
    elif mutation == "bad-status":
        result["suppressions"] = [{"kind": "inSource", "status": {}}]
    elif mutation == "bad-base":
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = []
    elif mutation == "bool-rule-index":
        result["ruleIndex"] = True
    elif mutation == "bad-region":
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = True
    elif mutation == "multiple-runs":
        sarif["runs"].append(copy.deepcopy(run))
    elif mutation == "multiple-invocations":
        run["invocations"].append(copy.deepcopy(run["invocations"][0]))
    elif mutation == "bad-success":
        run["invocations"][0]["executionSuccessful"] = 1
    with pytest.raises(ValueError):
        reconcile(native, sarif)


@pytest.mark.parametrize(
    "uri",
    [
        "https://host/active.py",
        "/src/../active.py",
        "/src/active.py?query",
        "/src/active.py#frag",
        "/src/%ZZ.py",
        "/src/%FF.py",
    ],
)
def test_sarif_uri_refuses_ambiguous_or_nonlocal_paths(uri: str) -> None:
    native, sarif = reports()
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = uri
    with pytest.raises(ValueError):
        reconcile(native, sarif)


def test_duplicate_json_and_report_budget_rejected() -> None:
    for raw in (b'{"version":1,"version":2}', b" " * (4 * 1024 * 1024 + 1)):
        with pytest.raises(ValueError):
            reconcile_semgrep_pass(
                profile_bytes=PROFILE,
                scope=scope(),
                execution_id="bad",
                role="research",
                native_json=raw,
                native_sarif=encoded(reports()[1]),
            )


@pytest.mark.parametrize("field", ["execution_id", "scope_sha256", "profile_sha256", "role"])
def test_dual_view_refuses_different_or_reused_treatment(field: str) -> None:
    research = reconcile(*reports())
    policy = reconcile(*reports(policy=True), role="repository-policy")
    raw = policy.model_dump(mode="json")
    raw[field] = getattr(research, field) if field in {"execution_id", "role"} else "f" * 64
    if field == "role":
        raw["findings"] = []
    with pytest.raises(ValueError):
        build_dual_view(research, SemgrepPassEvidence.model_validate(raw))


def test_derived_view_cannot_hide_or_reclassify_a_finding() -> None:
    raw = build_dual_view(
        reconcile(*reports()), reconcile(*reports(policy=True), role="repository-policy")
    ).model_dump(mode="json")
    raw["findings"][1]["state"] = "reported"
    with pytest.raises(ValueError):
        SemgrepDualView.model_validate(raw)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "unsorted",
        "policy-overlap",
        "non-python",
        "too-big",
        "bool-size",
        "traversal",
        "too-many",
    ],
)
def test_scope_is_bounded_sorted_disjoint_and_explicit(mutation: str) -> None:
    raw = scope().model_dump(mode="json")
    if mutation == "duplicate":
        raw["selected_files"].append(copy.deepcopy(raw["selected_files"][0]))
    elif mutation == "unsorted":
        raw["selected_files"].reverse()
    elif mutation == "policy-overlap":
        raw["policy_files"] = [copy.deepcopy(raw["selected_files"][0])]
    elif mutation == "non-python":
        raw["selected_files"][0]["path"] = "active.json"
    elif mutation == "too-big":
        raw["selected_files"][0]["byte_length"] = MAX_FILE_BYTES + 1
    elif mutation == "bool-size":
        raw["selected_files"][0]["byte_length"] = True
    elif mutation == "traversal":
        raw["selected_files"][0]["path"] = "../active.py"
    elif mutation == "too-many":
        raw["selected_files"] *= 22
    with pytest.raises(ValueError):
        SemgrepResearchScope.model_validate(raw)


def test_candidate_hash_checks_bind_every_rule_and_license() -> None:
    raw = load_research_profile(PROFILE).model_dump(mode="json")
    raw["rules"] = [raw["rules"][0]]
    raw["rules"][0]["sha256"] = sha256_bytes(b"rule")
    raw["source_license_sha256"] = sha256_bytes(b"license")
    profile = SemgrepResearchProfile.model_validate(raw)
    files = {profile.rules[0].source_path: b"rule"}
    verify_rule_bytes(profile, files, license_bytes=b"license")
    with pytest.raises(ValueError):
        verify_rule_bytes(profile, {}, license_bytes=b"license")
    with pytest.raises(ValueError):
        verify_rule_bytes(profile, files, license_bytes=b"changed")
    with pytest.raises(ValueError):
        verify_rule_bytes(
            profile, {profile.rules[0].source_path: b"changed"}, license_bytes=b"license"
        )
