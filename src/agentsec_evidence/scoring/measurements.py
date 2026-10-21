"""Evidence-domain adapters. Counts describe observations, never an overall security score."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.dependencies.analysis import package_set
from agentsec_evidence.models.contracts import Finding
from agentsec_evidence.reporting.dependency import PAIRS, load_dependency_run, summarize_dependency
from agentsec_evidence.reporting.models import (
    AgentSource,
    PublicPilotSource,
    ResearchSource,
    StaticSource,
)
from agentsec_evidence.reporting.service import load_report_source
from agentsec_evidence.scoring.calculations import (
    advisory_sets,
    condition_outcomes,
    count,
    field_retention,
    not_applicable,
    ratio,
)
from agentsec_evidence.scoring.models import MeasurementRow, Metric, Reference


@dataclass
class Context:
    project: Path
    session: str
    case: str
    role: Any
    attempt: str
    repetition: int
    references: tuple[Reference, ...]

    def ref(self, path: Path, pointer: str = "") -> Reference:
        return Reference(
            path=path.relative_to(self.project).as_posix(),
            sha256=sha256_file(path),
            pointer=pointer,
        )

    def row(
        self,
        stage: str,
        state: str,
        metrics: list[Metric],
        observations: dict[str, Any],
        refs: tuple[Reference, ...],
        *,
        repetition: int | None = None,
        analysis: Any = "not-established",
    ) -> MeasurementRow:
        repeat = self.repetition if repetition is None else repetition
        return MeasurementRow(
            row_id=semantic_hash(
                {
                    "session": self.session,
                    "attempt": self.attempt,
                    "stage": stage,
                    "repetition": repeat,
                }
            ),
            session=self.session,
            case_id=self.case,
            evidence_role=self.role,
            attempt_id=self.attempt,
            repetition=repeat,
            stage=stage,
            state=state,
            analysis_completeness=analysis,
            metrics=tuple(metrics),
            observations=json.loads(json.dumps(observations, allow_nan=False)),
            references=(*self.references, *refs),
        )


def semgrep_metrics(evidence: Any) -> list[Metric]:
    reported = sum(f.state in {"reported", "reported-with-native-issue"} for f in evidence.files)
    unknown = sum(f.state == "unreported" for f in evidence.files)
    return [
        ratio(
            "reported-path-coverage",
            reported,
            len(evidence.files),
            unit="selected-file-paths",
            eligibility="Every selected file; ignored/skipped files remain in the denominator",
            unknown=unknown,
            limitation="Reported paths do not prove per-rule or per-file completed analysis.",
        ),
        count(
            "native-rule-reports",
            len(evidence.findings),
            "native-rule-reports",
            "Not confirmed vulnerabilities; views/repeats are not additive.",
        ),
        count(
            "native-suppression-marked",
            sum(bool(f.native_suppressions) for f in evidence.findings),
            "native-rule-reports",
            "Native suppression is not reviewer approval.",
        ),
        count(
            "reported-with-native-issue",
            sum(f.state == "reported-with-native-issue" for f in evidence.files),
            "selected-file-paths",
            "Reports may coexist with native analysis issues.",
        ),
        count(
            "unreported-paths",
            unknown,
            "selected-file-paths",
            "Directory skip context is not an individual native file observation.",
        ),
        ratio(
            "analysis-completion",
            None,
            len(evidence.files),
            unit="selected-file-paths",
            eligibility="All selected files",
            unknown=len(evidence.files),
            limitation="Not observable from aggregate/native reported paths.",
        ),
    ]


def finding_fields(
    findings: list[Finding], run: dict[str, Any]
) -> tuple[list[Metric], dict[str, Any]]:
    """Compare explicit normalized fields with the export, not with security ground truth."""
    results = run["results"]
    indexed: dict[str, list[dict[str, Any]]] = {}
    for result in results:
        identity = result.get("partialFingerprints", {}).get("agentsecEvidenceRecord/v1", "")
        indexed.setdefault(identity, []).append(result)
    checks: list[tuple[str, object, object, bool]] = []
    for finding in findings:
        candidates = indexed.get(finding.fingerprints.record_v1, [])
        result = candidates[0] if len(candidates) == 1 else {}
        props = result.get("properties", {})
        native = finding.native_extension.get("agent_audit")
        native = native if isinstance(native, dict) else {}
        prefix = finding.record_id + ":"
        values = [
            ("rule-id", finding.rule.native_id, result.get("ruleId"), True),
            ("message", finding.message.title, result.get("message", {}).get("text"), True),
            (
                "native-severity",
                finding.severity.native_label,
                props.get("agentsecEvidence/nativeSeverity"),
                True,
            ),
            (
                "source-blob",
                finding.evidence[0].blob_sha256,
                props.get("agentsecEvidence/sourceBlobSha256"),
                True,
            ),
            (
                "json-pointer",
                finding.evidence[0].json_pointer,
                props.get("agentsecEvidence/jsonPointer"),
                True,
            ),
            (
                "record-fingerprint",
                finding.fingerprints.record_v1,
                result.get("partialFingerprints", {}).get("agentsecEvidenceRecord/v1"),
                True,
            ),
            ("native-confidence", finding.confidence.native_label, None, False),
            ("description", finding.message.description, None, False),
            ("remediation", finding.message.remediation, None, False),
            (
                "suppression",
                native.get("suppressed"),
                props.get("agentsecEvidence/nativeSuppressed"),
                True,
            ),
        ]
        for i, location in enumerate(finding.locations):
            locs = result.get("locations", [])
            physical = locs[i].get("physicalLocation", {}) if i < len(locs) else {}
            region = physical.get("region", {})
            uri = physical.get("artifactLocation", {}).get("uri")
            values.append(
                (f"location-{i}-path", location.artifact_path, unquote(uri) if uri else None, True)
            )
            for attr, sarif_name in (
                ("start_line", "startLine"),
                ("start_column", "startColumn"),
                ("end_line", "endLine"),
                ("end_column", "endColumn"),
            ):
                values.append(
                    (f"location-{i}-{attr}", getattr(location, attr), region.get(sarif_name), True)
                )
        checks.extend(
            (prefix + name, expected, actual, represented)
            for name, expected, actual, represented in values
        )
    assessed = field_retention(checks)
    applicable = sum(len(v) for k, v in assessed.items() if k != "not-present")
    metrics = [
        ratio(
            "normalized-to-sarif-field-retention",
            len(assessed["preserved"]),
            applicable,
            unit="present-reference-fields",
            eligibility="Explicit v1 field rubric; missing native fields excluded",
            excluded=len(assessed["not-present"]),
            limitation=(
                "Unrepresented fields remain available in original/normalized "
                "evidence; not a measure of claim correctness."
            ),
        ),
        count(
            "unrepresented-export-fields",
            len(assessed["unrepresented"]),
            "reference-fields",
            "Known export omissions are not invented values or discarded originals.",
        ),
        count(
            "incorrect-or-missing-export-fields",
            len(assessed["incorrect"]) + len(assessed["missing"]),
            "reference-fields",
            "Declared unrepresented fields are counted separately.",
        ),
        count(
            "ambiguous-export-identities",
            sum(len(v) != 1 for v in indexed.values()),
            "record-identities",
            "Duplicate fingerprints cannot establish faithful one-to-one export.",
        ),
    ]
    return metrics, {
        "field_rubric": assessed,
        "native_mapping_correctness": "not-adjudicated-by-fidelity-scoring",
    }


def dependency_rows(
    ctx: Context, root: Path, repetition: int, *, oracle: Path | None = None
) -> list[MeasurementRow]:
    run = load_dependency_run(root)
    summary = summarize_dependency(run)
    refs = (ctx.ref(root / "manifest.json"), ctx.ref(root / "report.json"))
    scope = run.scope
    eligible = set(scope.eligible) if scope else None
    rows: list[MeasurementRow] = []
    expected: dict[str, Any] | None = json.loads(oracle.read_bytes()) if oracle else None
    if expected and expected["database_sha256"] != summary.database_sha256:
        raise ValueError("Finite oracle database differs from retained evidence")
    for row in summary.stages:
        stage = run.stages.get(row.stage)
        metrics = [
            count(
                "identified-packages",
                row.identified_unique_packages,
                "pypi-name-version-pairs",
                "Not full qualified identities, occurrences or installed runtime.",
            ),
            count(
                "reported-package-advisory-pairs",
                row.reported_package_advisory_matches,
                "package-advisory-pairs",
                "Exact normalized package/version records only; unknown versions are "
                "not clean results.",
            ),
            count(
                "unsupported-package-observations",
                row.unsupported_observations,
                "package-observations",
                "Kept outside supported identity projection, never silently discarded.",
            ),
            ratio(
                "reported-package-visibility",
                row.eligible_reported_packages,
                len(eligible) if eligible is not None else None,
                unit="eligible-pypi-name-version-pairs",
                eligibility="Frozen lockfile-wide projection; local root separate",
                excluded=len(scope.separate_local) if scope else 0,
                unknown=row.unsupported_observations,
                limitation=(
                    "Visibility is not proof of ingestion or completed vulnerability matching."
                ),
            ),
            ratio(
                "matching-completion",
                None,
                len(eligible) if eligible is not None else None,
                unit="eligible-packages",
                eligibility="Frozen lockfile-wide package projection",
                unknown=None,
                limitation="OSV does not expose per-package matching completion in this treatment.",
            ),
        ]
        if not row.stage.startswith("osv-"):
            metrics = [
                not_applicable(
                    m.name, m.unit, "This stage records inventory, not advisory matching."
                )
                if m.name in {"reported-package-advisory-pairs", "matching-completion"}
                else m
                for m in metrics
            ]
        observations: dict[str, Any] = {
            "stage_limitations": stage.limitations if stage else ["No normalized stage"],
            "separate_local_packages": scope.separate_local if scope else None,
        }
        stage_refs = list(refs)
        if stage:
            stage_refs.append(ctx.ref(root / f"normalized/{row.stage}.json"))
            observations["package_identities"] = sorted(package_set(stage))
            observations["advisory_records"] = [m.model_dump(mode="json") for m in stage.matches]
        if expected is not None and stage is not None:
            authored = {tuple(v) for v in expected["eligible_packages"]}
            metrics.append(
                ratio(
                    "finite-inventory-recall",
                    len(package_set(stage) & authored),
                    len(authored),
                    unit="authored-pypi-name-version-pairs",
                    eligibility="Approved four-identity development fixture only",
                    limitation=expected["authorship"] + "; " + expected["review_status"],
                )
            )
            if row.stage.startswith("osv-"):
                observed, truth = advisory_sets(
                    stage.matches, {tuple(v) for v in expected["expected_matches"]}
                )
                valid = stage.state == "complete" and summary.state == "complete"
                tp = len(observed & truth) if valid else None
                for name, denom in (
                    ("finite-match-precision", len(observed)),
                    ("finite-match-recall", len(truth)),
                ):
                    metrics.append(
                        ratio(
                            name,
                            tp,
                            denom,
                            unit="package-alias-group-pairs",
                            eligibility=(
                                "Student-confirmed finite oracle against "
                                "frozen advisory records; not independent "
                                "external labels"
                            ),
                            unknown=0 if valid else None,
                            limitation=(
                                "Partial/missing/error analysis is unscored, never a true negative."
                            ),
                        )
                    )
                observations["unexpected_pairs"] = sorted(observed - truth)
                observations["missing_pairs"] = sorted(truth - observed)
            assert oracle is not None
            stage_refs.append(ctx.ref(oracle))
        if row.stage.startswith("osv-"):
            native_path = root / f"native/{row.stage}/osv.json"
            if native_path.is_file():
                native = json.loads(native_path.read_bytes())
                packages = [p for r in native.get("results", []) for p in r.get("packages", [])]
                unknown_packages = [
                    p
                    for p in packages
                    if p.get("package", {}).get("version") in (None, "", "UNKNOWN")
                ]
                observations["unknown_version_native_advisory_records"] = sum(
                    len(p.get("vulnerabilities", [])) for p in unknown_packages
                )
                observations["unknown_version_native_groups"] = sum(
                    len(p.get("groups", [])) for p in unknown_packages
                )
                observations["unknown_version_interpretation"] = (
                    "Native advisories without an exact version are not confirmed "
                    "exact package-version matches; zero normalized matches is not "
                    "safe."
                )
                stage_refs.append(ctx.ref(native_path))
        rows.append(
            ctx.row(
                row.stage,
                row.state,
                metrics,
                observations,
                tuple(stage_refs),
                repetition=repetition,
                analysis="incomplete" if row.state != "complete" else "not-established",
            )
        )
    for comparison in summary.comparisons:
        fraction = comparison.package_projection_retention
        metric = ratio(
            "package-projection-retention",
            fraction.numerator if fraction else None,
            fraction.denominator if fraction else None,
            unit="eligible-pypi-name-version-pairs",
            eligibility="Left-stage eligible unique name/version projection",
            unknown=len(comparison.missing_identifiers),
            limitation="Does not establish source-qualifier, occurrence or relationship fidelity.",
        )
        rows.append(
            ctx.row(
                f"{comparison.left}-to-{comparison.right}",
                "comparable" if comparison.comparable else "not-comparable",
                [
                    metric,
                    count(
                        "source-qualifier-losses",
                        len(comparison.source_qualifier_losses),
                        "package-projections",
                        "Losses are preserved beside the projection ratio.",
                    ),
                    ratio(
                        "relationship-fidelity",
                        None,
                        None,
                        unit="dependency-relationships",
                        eligibility="No independent edge oracle in this scoring treatment",
                        unknown=None,
                        limitation=(
                            "Component identity retention does not establish "
                            "dependency-edge preservation."
                        ),
                    ),
                ],
                comparison.model_dump(mode="json"),
                refs,
                repetition=repetition,
            )
        )
    for left, right in PAIRS:
        if not any(c.left == left and c.right == right for c in summary.comparisons):
            rows.append(
                ctx.row(
                    f"{left}-to-{right}",
                    "missing-comparison",
                    [
                        ratio(
                            "package-projection-retention",
                            None,
                            None,
                            unit="eligible-pypi-name-version-pairs",
                            eligibility="Both retained stages and scope required",
                            unknown=None,
                            limitation="Missing stage/scope; cannot infer zero discrepancy.",
                        )
                    ],
                    {},
                    refs,
                    repetition=repetition,
                )
            )
    rows.append(
        ctx.row(
            "dependency-path-timing",
            summary.state,
            [
                count(
                    key,
                    summary.timing_ns.get(key),
                    "nanoseconds",
                    "Retained wall time; preparation/download excluded, first-use "
                    "SBOM path includes Syft; no controlled performance claim.",
                )
                for key in (
                    "direct_path_wall_ns",
                    "sbom_initial_path_wall_ns",
                    "sbom_consumer_only_wall_ns",
                    "paired_end_to_end_ns",
                )
            ],
            {"historical_human_preparation_time_ns": None},
            refs,
            repetition=repetition,
        )
    )
    return rows


def source_rows(
    ctx: Context, root: Path, *, expectation: dict[str, Any] | None = None
) -> list[MeasurementRow]:
    source, document = load_report_source(ctx.project, root)
    if source.kind == "custom-repair":
        raise ValueError("Custom repair evidence is not admitted to benchmark scoring")
    sarif_runs = cast(list[dict[str, Any]], document["runs"])
    rows: list[MeasurementRow] = []
    refs: tuple[Reference, ...]
    if isinstance(source, PublicPilotSource):
        summary = source.summary
        refs = (ctx.ref(root / "evidence-manifest.json"), ctx.ref(root / "pilot-report.json"))
        rows.extend(
            ctx.row(
                input_plan.tool_id + "-input-decisions",
                "verified",
                [
                    ratio(
                        "input-decision-accounting",
                        len(input_plan.selections),
                        len(summary.inventory.records),
                        unit="git-verified-files",
                        eligibility="Full pinned-revision inventory, including excluded files",
                        limitation=(
                            "Inventory/input decisions are not scanning or detection coverage."
                        ),
                    )
                ],
                {
                    "selected_paths": summary.plan.python_paths,
                    "dockerfile": summary.plan.dockerfile,
                },
                refs,
                repetition=0,
            )
            for input_plan in summary.input_plans
        )
        for rep in summary.repetitions:
            for label, view in (
                ("semgrep-research", rep.semgrep.research),
                ("semgrep-policy", rep.semgrep.repository_policy),
            ):
                assert view is not None
                stage_row = next(
                    r for r in summary.rows if r.repetition == rep.repetition and r.stage == label
                )
                rows.append(
                    ctx.row(
                        label,
                        stage_row.state,
                        semgrep_metrics(view),
                        {
                            "semantic_sha256": stage_row.semantic_sha256,
                            "directory_skip_context": [
                                s.model_dump(mode="json") for s in rep.directory_skips[view.role]
                            ],
                        },
                        (*refs, ctx.ref(root / f"repetition-{rep.repetition}/{label}/native.json")),
                        repetition=rep.repetition,
                    )
                )
            exported = next(
                run
                for run in sarif_runs
                if run["properties"].get("agentsecEvidence/nativeRunId") == rep.agent_run_id
            )
            metrics, details = finding_fields(rep.agent_findings, exported)
            metrics.extend(
                [
                    count(
                        "native-rule-reports",
                        len(rep.agent_findings),
                        "native-rule-reports",
                        "No exhaustive public oracle; eight reports are not eight "
                        "confirmed vulnerabilities.",
                    ),
                    count(
                        "native-aggregate-files",
                        rep.agent_native_scanned_files,
                        "native-aggregate-count",
                        "Incompatible with per-file identities; never divide by "
                        "selected file count.",
                    ),
                    ratio(
                        "analysis-completion",
                        None,
                        len(summary.plan.python_paths),
                        unit="selected-files",
                        eligibility="All selected Python files",
                        unknown=len(summary.plan.python_paths),
                        limitation="Native aggregate count does not expose per-file completion.",
                    ),
                ]
            )
            rows.append(
                ctx.row(
                    "agent-audit",
                    "partial",
                    metrics,
                    details,
                    (
                        *refs,
                        ctx.ref(root / f"repetition-{rep.repetition}/agent-audit/native.json"),
                        ctx.ref(root / f"repetition-{rep.repetition}/agent-audit/results.sarif"),
                    ),
                    repetition=rep.repetition,
                )
            )
            manifests = list(
                (root / f"repetition-{rep.repetition}").glob("**/dependency-runs/*/manifest.json")
            )
            if len(manifests) != 1:
                raise ValueError("Pilot dependency constituent is ambiguous")
            rows.extend(dependency_rows(ctx, manifests[0].parent, rep.repetition))
        for stage in summary.repeatability:
            hashes = [r.semantic_sha256 for r in summary.rows if r.stage == stage]
            known = all(h is not None for h in hashes)
            rows.append(
                ctx.row(
                    "repeatability-" + stage,
                    "observed",
                    [
                        ratio(
                            "semantic-agreement-to-first",
                            sum(h == hashes[0] for h in hashes[1:]) if known else None,
                            len(hashes) - 1,
                            unit="within-treatment-repeat-comparisons",
                            eligibility=(
                                "Compare repetitions 2/3 against repetition "
                                "1; one repository, not independent samples"
                            ),
                            unknown=0 if known else None,
                            limitation=(
                                "Only the recorded stage-specific semantic "
                                "projection; raw bytes retained."
                            ),
                        )
                    ],
                    {"semantic_hashes": hashes},
                    refs,
                    repetition=0,
                )
            )
        rows.append(
            ctx.row(
                "pilot-wall-time",
                "partial",
                [
                    count(
                        "attempt-wall-time",
                        summary.attempt_wall_ns,
                        "nanoseconds",
                        "Includes retained first-use workflow; not a controlled "
                        "performance comparison.",
                    ),
                    count(
                        "recorded-manual-recovery-actions",
                        summary.manual_recovery_actions_during_attempt,
                        "actions",
                        "Does not include unmeasured preparation, interpretation or "
                        "research effort.",
                    ),
                    count(
                        "human-preparation-and-review-time",
                        None,
                        "nanoseconds",
                        "Not prospectively measured in the retained pilot.",
                    ),
                ],
                {},
                refs,
                repetition=0,
            )
        )
    elif isinstance(source, ResearchSource):
        summary_r = source.summary
        refs = (ctx.ref(root.parent / "evidence-manifest.json"),)
        rows.extend(
            ctx.row(
                p.evidence.role,
                p.execution.analysis_state,
                semgrep_metrics(p.evidence),
                {"native_exit_code": p.exit_code, "duration_ns": p.duration_ns},
                (
                    *refs,
                    ctx.ref(root.parent / p.native_json_path),
                    ctx.ref(root.parent / p.native_sarif_path),
                ),
                repetition=p.repetition,
                analysis="incomplete"
                if p.execution.analysis_state == "incomplete"
                else "not-established",
            )
            for p in summary_r.passes
        )
        if not summary_r.passes:
            rows.append(
                ctx.row(
                    "research-input-gate",
                    summary_r.state,
                    [
                        count(
                            "native-rule-reports",
                            None,
                            "native-rule-reports",
                            "Scanner not run; refusal is not a true negative.",
                        )
                    ],
                    {
                        "syntax_state": summary_r.syntax_state,
                        "policy": summary_r.policy.model_dump(mode="json"),
                    },
                    refs,
                    analysis="not-run",
                )
            )
    elif isinstance(source, StaticSource | AgentSource):
        from agentsec_evidence.operations.offline import load_existing_run

        existing = load_existing_run(root.parent.parent, root.name)
        findings = list(existing.findings)
        metrics, details = finding_fields(findings, sarif_runs[0])
        if expectation is not None and ctx.case == "dev-semgrep-basic-v1":
            expected = {expectation["positive_path"]: True, expectation["corrected_path"]: False}
            observed = {
                loc.artifact_path
                for f in findings
                if f.rule.native_id == expectation["expected_rule_id"]
                for loc in f.locations
            }
            eligible = source.state == "complete"
            eligible = eligible and bool(existing.parser_report and existing.parser_report.complete)
            outcomes = condition_outcomes(expected, observed, analysis_eligible=eligible)
            details["finite_rule_path_outcomes"] = outcomes
            details["expectation"] = expectation
            metrics.append(
                ratio(
                    "finite-rule-path-agreement",
                    (outcomes["tp"] or 0) + (outcomes["tn"] or 0) if eligible else None,
                    len(expected),
                    unit="authored-rule-path-conditions",
                    eligibility="Original eval rule on positive and corrected authored paths only",
                    unknown=0 if eligible else len(expected),
                    limitation=(
                        "Engineering rule/path assertions, "
                        "not independent vulnerability adjudication."
                    ),
                )
            )
        native_count = (
            source.agent_details.native_result_count
            if isinstance(source, AgentSource)
            else existing.parser_report.native_result_count
            if existing.parser_report
            else None
        )
        metrics.extend(
            [
                count(
                    "native-rule-reports",
                    native_count,
                    "native-rule-reports",
                    "Not independently verified security conditions.",
                ),
                count(
                    "retained-normalized-records",
                    len(findings),
                    "finding-records",
                    "Zero stored records for refused inputs is not a clean scan.",
                ),
                count(
                    "native-duration",
                    source.summary.duration_ns,
                    "nanoseconds",
                    "Retained process wall time; not performance inference.",
                ),
            ]
        )
        rows.append(
            ctx.row(
                existing.execution.producer.tool_id,
                source.state,
                metrics,
                details,
                (ctx.ref(root / "bundle-manifest.json"), ctx.ref(root / "exports/results.sarif")),
                analysis="not-established" if native_count is not None else "not-run",
            )
        )
    return rows
