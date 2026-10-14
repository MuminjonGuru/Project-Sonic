"""New immutable review revisions, bound to validated reports; never modify native findings."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.models import CommonReport, PublicPilotSource
from agentsec_evidence.reporting.service import require_new_derivative, validate_common_report
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.reviews.models import (
    ReviewAnnotation,
    ReviewBatch,
    ReviewManifest,
    ReviewSidecar,
    annotation_sha256,
)

MAX_REVIEW_BYTES = 8 * 1024**2
MAX_REPORT_BYTES = 16 * 1024**2
MAX_SARIF_BYTES = 64 * 1024**2


def _report(project: Path, root: Path) -> tuple[CommonReport, str]:
    root = plain_path(root, directory=True)
    before = bounded_file(root / "report-manifest.json", MAX_REVIEW_BYTES)
    raw = bounded_file(root / "report.json", MAX_REPORT_BYTES)
    # Apply review input limits before the existing derivative validator parses these files.
    sarif = bounded_file(root / "results.sarif", MAX_SARIF_BYTES)
    validate_common_report(project, root)
    manifest = load_agent_json(before, max_bytes=MAX_REVIEW_BYTES)
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError("Report manifest entries are missing")
    matches = [e for e in entries if isinstance(e, dict) and e.get("path") == "report.json"]
    if len(matches) != 1:
        raise ValueError("Report manifest must identify exactly one report")
    entry = matches[0]
    sarif_matches = [e for e in entries if isinstance(e, dict) and e.get("path") == "results.sarif"]
    if len(sarif_matches) != 1 or (
        sha256_bytes(sarif) != sarif_matches[0].get("sha256")
        or len(sarif) != sarif_matches[0].get("bytes")
    ):
        raise ValueError("Report SARIF changed during review validation")
    if (
        sha256_bytes(raw) != entry["sha256"]
        or len(raw) != entry["bytes"]
        or bounded_file(root / "report-manifest.json", MAX_REVIEW_BYTES) != before
    ):
        raise ValueError("Report changed during review validation")
    return CommonReport.model_validate(
        load_agent_json(raw, max_bytes=MAX_REPORT_BYTES)
    ), sha256_bytes(before)


def bind_review(sidecar: ReviewSidecar, report: CommonReport, report_sha256: str) -> None:
    if sidecar.report_manifest_sha256 != report_sha256:
        raise ValueError("Review refers to another common report")
    sources = {s.run_id: s for s in report.sources if isinstance(s, PublicPilotSource)}
    for annotation in sidecar.annotations:
        subject = annotation.subject
        source = sources.get(subject.source_run_id)
        if source is None or source.source_manifest_sha256 != subject.source_manifest_sha256:
            raise ValueError("Review requires an exact public-pilot source identity")
        candidates = [
            f
            for rep in source.summary.repetitions
            for f in rep.agent_findings
            if (source.run_id, f.run_id, f.execution_id, f.record_id) == subject.key
        ]
        if (
            len(candidates) != 1
            or semantic_hash(candidates[0].model_dump(mode="json")) != subject.finding_sha256
        ):
            raise ValueError("Review finding does not match its original report snapshot")
        inventory = {r.source.path: r.source.sha256 for r in source.summary.inventory.records}
        for context in annotation.contexts:
            if inventory.get(context.artifact_path) != context.source_sha256:
                raise ValueError("Review context is not bound to the source inventory")


def _read_sidecar(root: Path) -> tuple[ReviewSidecar, str]:
    root = plain_path(root, directory=True)
    if {p.name for p in root.iterdir()} != {"review.json", "review-manifest.json"}:
        raise ValueError("Review directory must contain exactly its sidecar and manifest")
    manifest_bytes = bounded_file(root / "review-manifest.json", MAX_REVIEW_BYTES)
    manifest = ReviewManifest.model_validate(
        load_agent_json(manifest_bytes, max_bytes=MAX_REVIEW_BYTES)
    )
    raw = bounded_file(root / "review.json", MAX_REVIEW_BYTES)
    if len(raw) != manifest.review_bytes or sha256_bytes(raw) != manifest.review_sha256:
        raise ValueError("Review file differs from its manifest")
    sidecar = ReviewSidecar.model_validate(load_agent_json(raw, max_bytes=MAX_REVIEW_BYTES))
    if (
        sidecar.report_manifest_sha256 != manifest.report_manifest_sha256
        or len(sidecar.annotations) != manifest.annotation_count
    ):
        raise ValueError("Review manifest binding differs")
    return sidecar, manifest.review_sha256


def write_review(
    *,
    project: Path,
    report_root: Path,
    batch_path: Path,
    output: Path,
    previous: Path | None = None,
) -> ReviewSidecar:
    # Every correction creates a new directory. Neither reports nor earlier review revisions change.
    protected = [report_root, *([previous] if previous is not None else [])]
    for parent in (output.absolute(), *output.absolute().parents):
        if parent.exists():
            plain_path(parent, directory=True)
        if (parent / "review-manifest.json").exists():
            raise ValueError("Review output cannot modify a prior review bundle")
    destination = require_new_derivative(output, protected)
    report, report_sha = _report(project, report_root)
    raw_batch = bounded_file(batch_path, MAX_REVIEW_BYTES)
    batch = ReviewBatch.model_validate(load_agent_json(raw_batch, max_bytes=MAX_REVIEW_BYTES))
    old: tuple[ReviewAnnotation, ...] = ()
    previous_sha = None
    if previous is not None:
        prior, previous_sha = _read_sidecar(previous)
        bind_review(prior, report, report_sha)
        old = prior.annotations
    sidecar = ReviewSidecar(
        report_manifest_sha256=report_sha,
        previous_review_sha256=previous_sha,
        previous_annotation_count=len(old),
        annotations=(*old, *batch.annotations),
    )
    bind_review(sidecar, report, report_sha)
    payload = json_bytes(sidecar.model_dump(mode="json"))
    if len(payload) > MAX_REVIEW_BYTES:
        raise ValueError("Review sidecar exceeds byte budget")
    manifest = ReviewManifest(
        review_sha256=sha256_bytes(payload),
        review_bytes=len(payload),
        report_manifest_sha256=report_sha,
        annotation_count=len(sidecar.annotations),
    )
    # Recheck exact inputs before publishing a new derivative; this is not identity attestation.
    if (
        sha256_bytes(bounded_file(report_root / "report-manifest.json", MAX_REVIEW_BYTES))
        != report_sha
    ):
        raise ValueError("Report manifest changed before writing review")
    if (
        previous is not None
        and sha256_bytes(bounded_file(previous / "review.json", MAX_REVIEW_BYTES)) != previous_sha
    ):
        raise ValueError("Prior review changed before writing revision")
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in (
        ("review.json", payload),
        ("review-manifest.json", json_bytes(manifest.model_dump(mode="json"))),
    ):
        with (destination / name).open("xb") as handle:
            handle.write(content)
    return sidecar


def validate_review(
    *,
    project: Path,
    report_root: Path,
    root: Path,
    previous: Path | None = None,
) -> dict[str, JsonValue]:
    report, report_sha = _report(project, report_root)
    sidecar, review_sha = _read_sidecar(root)
    bind_review(sidecar, report, report_sha)
    if previous is not None:
        prior, prior_sha = _read_sidecar(previous)
        bind_review(prior, report, report_sha)
        if (
            sidecar.previous_review_sha256 != prior_sha
            or sidecar.previous_annotation_count != len(prior.annotations)
            or sidecar.annotations[: len(prior.annotations)] != prior.annotations
        ):
            raise ValueError("Review revision is not an append-only extension of its predecessor")
    latest = {a.review_id: a for a in sidecar.annotations}
    return {
        "passed": True,
        "contract": sidecar.contract,
        "review_sha256": review_sha,
        "report_manifest_sha256": report_sha,
        "annotation_count": len(sidecar.annotations),
        "human_decision_occurrences": sum(a.decision != "proposed" for a in latest.values()),
        "pending_finding_occurrences": sum(a.decision == "proposed" for a in latest.values()),
        "vulnerability_total": None,
        "previous_revision_check": "verified"
        if previous is not None
        else "not-provided"
        if sidecar.previous_review_sha256
        else "not-applicable",
        "identity_assurance": sidecar.reviewer_identity_assurance,
        "validation_scope": "report-derivative-and-review-bindings",
        "original_source_bundles_revalidated": False,
        "latest": cast(
            list[JsonValue],
            [
                {
                    "review_id": key,
                    "annotation_sha256": annotation_sha256(a),
                    "decision": a.decision,
                    "conclusion": a.conclusion,
                    "reviewer_role": a.reviewer.role,
                }
                for key, a in sorted(latest.items())
            ],
        ),
    }
