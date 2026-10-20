"""Bounded read-only inputs for presentation; never follow native-evidence pointers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import JsonValue

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.reporting.custom_models import CustomCommonReport
from agentsec_evidence.reporting.models import CommonReport
from agentsec_evidence.reporting.service import parse_common_report, validate_common_report
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.reviews.models import ReviewSidecar
from agentsec_evidence.reviews.service import bind_review, validate_review

REPORT_LIMITS = {
    "report-manifest.json": 1024**2,
    "report.json": 16 * 1024**2,
    "results.sarif": 64 * 1024**2,
}
REVIEW_LIMITS = {"review-manifest.json": 1024**2, "review.json": 8 * 1024**2}


@dataclass(frozen=True)
class PresentationFile:
    group: Literal["report", "review"]
    path: Path
    data: bytes

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.data)

    def reference(self) -> dict[str, JsonValue]:
        return {
            "group": self.group,
            "name": self.path.name,
            "sha256": self.sha256,
            "bytes": len(self.data),
        }


@dataclass(frozen=True)
class PresentationInputs:
    report: CommonReport
    sarif: dict[str, JsonValue]
    review: ReviewSidecar | None
    review_validation: dict[str, JsonValue] | None
    files: tuple[PresentationFile, ...]

    def file(self, group: str, name: str) -> PresentationFile:
        return next(f for f in self.files if f.group == group and f.path.name == name)

    @property
    def report_manifest_sha256(self) -> str:
        return self.file("report", "report-manifest.json").sha256


def _snapshot(root: Path, group: Literal["report", "review"]) -> tuple[PresentationFile, ...]:
    root = plain_path(root, directory=True)
    limits = REPORT_LIMITS if group == "report" else REVIEW_LIMITS
    if {p.name for p in root.iterdir()} != set(limits):
        raise ValueError("Unexpected presentation input file set")
    result = tuple(
        PresentationFile(group, root / name, bounded_file(root / name, limit))
        for name, limit in sorted(limits.items())
    )
    # Reject duplicate keys and excessive structures before legacy validators parse the files.
    for item in result:
        load_agent_json(item.data, max_bytes=limits[item.path.name])
    return result


def verify_presentation_inputs_unchanged(inputs: PresentationInputs) -> None:
    for group in ("report", "review"):
        selected = tuple(f for f in inputs.files if f.group == group)
        if selected and _snapshot(selected[0].path.parent, selected[0].group) != selected:
            raise ValueError("Presentation inputs changed during processing")


def read_presentation_inputs(
    project: Path, report_root: Path, *, review_root: Path | None = None
) -> PresentationInputs:
    files = _snapshot(report_root, "report")
    if review_root is not None:
        files += _snapshot(review_root, "review")
    validate_common_report(project, report_root)
    raw = {f.path.name: f.data for f in files}
    report = parse_common_report(raw["report.json"])
    if isinstance(report, CustomCommonReport):
        raise ValueError(
            "Custom-family HTML/review presentation is not yet supported; use report JSON/SARIF"
        )
    sarif = load_agent_json(raw["results.sarif"], max_bytes=REPORT_LIMITS["results.sarif"])
    review, checked = None, None
    if review_root is not None:
        checked = validate_review(project=project, report_root=report_root, root=review_root)
        review = ReviewSidecar.model_validate(
            load_agent_json(raw["review.json"], max_bytes=REVIEW_LIMITS["review.json"])
        )
        bind_review(review, report, sha256_bytes(raw["report-manifest.json"]))
    result = PresentationInputs(report, sarif, review, checked, files)
    verify_presentation_inputs_unchanged(result)
    return result
