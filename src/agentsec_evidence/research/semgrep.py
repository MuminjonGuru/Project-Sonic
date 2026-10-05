from __future__ import annotations

import re
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import JsonValue

from agentsec_evidence.adapters.semgrep import parse_semgrep_json
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.research.models import (
    MAX_REPORT_BYTES,
    FindingAnchor,
    ResearchFileObservation,
    ResearchFinding,
    SemgrepDualView,
    SemgrepPassEvidence,
    SemgrepResearchScope,
    load_research_profile,
    policy_observations,
)


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("Expected a native JSON object")
    return value


def _array(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ValueError("Expected a native JSON array")
    return value


def _text(value: JsonValue) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected nonempty native text")
    return value


def _path(value: JsonValue, *, sarif: bool = False) -> str:
    path = _text(value)
    if sarif:
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ValueError("Control character in native URI")
        if re.search(r"%(?![0-9A-Fa-f]{2})", path):
            raise ValueError("Malformed percent-encoded native path")
        uri = urlsplit(path)
        if uri.scheme or uri.netloc or uri.query or uri.fragment:
            raise ValueError("Native SARIF location must be a local source path")
        path = unquote(uri.path, encoding="utf-8", errors="strict")
    return canonical_artifact_path(path.removeprefix("/src/"))


def _json_anchor(value: dict[str, JsonValue]) -> FindingAnchor:
    start, end = _object(value.get("start")), _object(value.get("end"))
    return FindingAnchor.model_validate(
        {
            "rule_id": value.get("check_id"),
            "path": _path(value.get("path")),
            "start_line": start.get("line"),
            "start_column": start.get("col"),
            "end_line": end.get("line"),
            "end_column": end.get("col"),
        }
    )


def _sarif_anchor(value: dict[str, JsonValue]) -> FindingAnchor:
    locations = _array(value.get("locations"))
    if len(locations) != 1:
        raise ValueError("Exactly one native finding location is supported")
    location = _object(_object(locations[0]).get("physicalLocation"))
    artifact = _object(location.get("artifactLocation"))
    if artifact.get("uriBaseId") not in (None, "%SRCROOT%", "SRCROOT"):
        raise ValueError("Unsupported SARIF source base")
    region = _object(location.get("region"))
    return FindingAnchor.model_validate(
        {
            "rule_id": value.get("ruleId"),
            "path": _path(artifact.get("uri"), sarif=True),
            "start_line": region.get("startLine"),
            "start_column": region.get("startColumn"),
            "end_line": region.get("endLine"),
            "end_column": region.get("endColumn"),
        }
    )


def _suppression_records(value: dict[str, JsonValue]) -> tuple[dict[str, JsonValue], ...]:
    records = tuple(_object(item) for item in _array(value.get("suppressions", [])))
    for item in records:
        if item.get("kind") not in ("inSource", "external"):
            raise ValueError("Unsupported native suppression kind")
        if item.get("status") not in (None, "accepted", "underReview", "rejected"):
            raise ValueError("Unsupported native suppression status")
    return records


def reconcile_semgrep_pass(
    *,
    profile_bytes: bytes,
    scope: SemgrepResearchScope,
    execution_id: str,
    role: Literal["research", "repository-policy"],
    native_json: bytes,
    native_sarif: bytes,
) -> SemgrepPassEvidence:
    """Join paired native evidence, not vulnerability identities or security verdicts.

    Callers retain both native byte streams even when reconciliation raises. The derivative
    does not validate subprocess completion, source acquisition or permission to run a scanner.
    """
    profile = load_research_profile(profile_bytes)
    checked = SemgrepResearchScope.model_validate(scope.model_dump(mode="json"))
    if checked.profile_sha256 != sha256_bytes(profile_bytes):
        raise ValueError("Scope refers to different profile bytes")
    raw = load_agent_json(native_json, max_bytes=MAX_REPORT_BYTES)
    sarif = load_agent_json(native_sarif, max_bytes=MAX_REPORT_BYTES)
    parsed = parse_semgrep_json(native_json).document
    if parsed.version != profile.tool_version or sarif.get("version") != "2.1.0":
        raise ValueError("Native version differs from supported treatment")
    runs = _array(sarif.get("runs"))
    if len(runs) != 1:
        raise ValueError("Exactly one native SARIF run is supported")
    run = _object(runs[0])
    driver = _object(_object(run.get("tool")).get("driver"))
    if (
        driver.get("name") not in ("Semgrep", "Semgrep OSS")
        or driver.get("semanticVersion") != profile.tool_version
    ):
        raise ValueError("Native SARIF producer differs")
    if run.get("columnKind") not in (None, "unicodeCodePoints"):
        raise ValueError("Unsupported SARIF column convention")
    declared = tuple(_text(_object(rule).get("id")) for rule in _array(driver.get("rules")))
    allowed = {rule.native_rule_id for rule in profile.rules}
    if len(set(declared)) != len(declared) or not set(declared).issubset(allowed):
        raise ValueError("Native rule declarations differ from candidate")
    selected = {item.path for item in checked.selected_files}
    scanned = [_path(path) for path in parsed.paths.scanned]
    if len(set(scanned)) != len(scanned) or not set(scanned).issubset(selected):
        raise ValueError("Native reported paths differ from selected inputs")
    skipped: dict[str, str] = {}
    for item in parsed.paths.skipped:
        entry = _object(item)
        path = _path(entry.get("path"))
        # Policy files can be listed as skipped non-Python inputs but are not scanner targets.
        if path in {item.path for item in checked.policy_files}:
            continue
        if path not in selected or path in skipped:
            raise ValueError("Native skipped paths are foreign or repeated")
        reason = _text(entry.get("reason"))
        if path in scanned and reason in {
            "semgrepignore_patterns_match",
            "gitignore_patterns_match",
        }:
            raise ValueError("Native policy exclusion contradicts a reported path")
        skipped[path] = reason
    json_results: dict[FindingAnchor, tuple[int, dict[str, JsonValue]]] = {}
    for index, item in enumerate(_array(raw.get("results"))):
        result = _object(item)
        anchor = _json_anchor(result)
        if anchor in json_results:
            raise ValueError("Ambiguous repeated JSON finding anchor")
        json_results[anchor] = (index, result)
    findings: list[ResearchFinding] = []
    seen: set[FindingAnchor] = set()
    for index, item in enumerate(_array(run.get("results"))):
        result = _object(item)
        anchor = _sarif_anchor(result)
        if anchor in seen or anchor.rule_id not in declared or anchor.path not in scanned:
            raise ValueError("Ambiguous, undeclared or unreported SARIF finding")
        seen.add(anchor)
        if "ruleIndex" in result:
            rule_index = result["ruleIndex"]
            if (
                type(rule_index) is not int
                or not 0 <= rule_index < len(declared)
                or declared[rule_index] != anchor.rule_id
            ):
                raise ValueError("SARIF rule index differs from rule ID")
        message = _text(_object(result.get("message")).get("text"))
        suppressions = _suppression_records(result)
        match = json_results.get(anchor)
        pointer = None
        if match is not None:
            native_index, native = match
            if _object(native.get("extra")).get("message") != message:
                raise ValueError("JSON and SARIF finding messages differ")
            pointer = f"/results/{native_index}"
        elif role == "research" or not suppressions:
            raise ValueError("Unexplained native finding missing from JSON")
        findings.append(
            ResearchFinding(
                anchor=anchor,
                message=message,
                json_pointer=pointer,
                sarif_pointer=f"/runs/0/results/{index}",
                native_suppressions=suppressions,
            )
        )
    if set(json_results) != seen.intersection(json_results):
        raise ValueError("Native JSON finding missing from SARIF")
    invocations = _array(run.get("invocations", []))
    if len(invocations) > 1:
        raise ValueError("Multiple native SARIF invocation records are unsupported")
    invocation = _object(invocations[0]) if invocations else {}
    successful = invocation.get("executionSuccessful")
    if successful is not None and type(successful) is not bool:
        raise ValueError("Native execution-success flag must be boolean")
    observations = tuple(
        ResearchFileObservation(
            path=path,
            state="reported-with-native-issue"
            if path in scanned and path in skipped
            else "reported"
            if path in scanned
            else "native-skipped"
            if path in skipped
            else "unreported",
            native_reason=skipped.get(path),
        )
        for path in sorted(selected)
    )
    return SemgrepPassEvidence(
        profile_sha256=sha256_bytes(profile_bytes),
        scope_sha256=semantic_hash(checked.model_dump(mode="json")),
        execution_id=execution_id,
        role=role,
        native_json_sha256=sha256_bytes(native_json),
        native_sarif_sha256=sha256_bytes(native_sarif),
        files=observations,
        findings=tuple(findings),
        native_errors=tuple(parsed.errors),
        native_skipped_rules=tuple(parsed.skipped_rules),
        native_execution_successful=successful,
        native_notifications=tuple(_array(invocation.get("toolExecutionNotifications", []))),
        native_skip_details_available="skipped" in _object(raw.get("paths")),
        native_declared_rule_ids=tuple(sorted(declared)),
    )


def build_dual_view(
    research: SemgrepPassEvidence, policy: SemgrepPassEvidence | None = None
) -> SemgrepDualView:
    checked = SemgrepPassEvidence.model_validate(research.model_dump(mode="json"))
    checked_policy = (
        SemgrepPassEvidence.model_validate(policy.model_dump(mode="json")) if policy else None
    )
    return SemgrepDualView(
        research=checked,
        repository_policy=checked_policy,
        findings=policy_observations(checked, checked_policy),
        policy_state="observed" if checked_policy else "not-run",
    )
