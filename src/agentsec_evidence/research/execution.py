from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.research.models import (
    ResearchModel,
    SemgrepPassEvidence,
    SemgrepResearchScope,
    load_research_profile,
)


class ResearchExecutionAssessment(ResearchModel):
    contract: Literal["semgrep-execution-assessment-v1"] = "semgrep-execution-assessment-v1"
    process_state: Literal[
        "completed", "nonzero", "timed-out", "output-limited", "exit-unavailable"
    ]
    cleanup_succeeded: bool
    report_state: Literal["reconciled", "missing-or-invalid"]
    analysis_state: Literal["not-established", "incomplete", "failed"]
    reasons: tuple[str, ...]
    vulnerability_total: None = None


def assess_research_execution(
    capture: ProcessCapture,
    *,
    cleanup_succeeded: bool,
    evidence: SemgrepPassEvidence | None,
) -> ResearchExecutionAssessment:
    """A native exit is process evidence, not a finding count or proof of complete analysis."""
    state: Literal["completed", "nonzero", "timed-out", "output-limited", "exit-unavailable"]
    state = (
        "timed-out"
        if capture.timed_out
        else "output-limited"
        if capture.output_limited or capture.stdout_truncated or capture.stderr_truncated
        else "exit-unavailable"
        if capture.exit_code is None
        else "completed"
        if capture.exit_code == 0
        else "nonzero"
    )
    reasons: list[str] = []
    if state != "completed":
        reasons.append("process-" + state)
    if not cleanup_succeeded:
        reasons.append("container-cleanup-failed")
    if evidence is None:
        reasons.append("paired-native-reports-missing-or-invalid")
    failed = (
        state in {"timed-out", "output-limited", "exit-unavailable"}
        or not cleanup_succeeded
        or evidence is None
        or capture.exit_code not in {0, 2}
    )
    if evidence is not None:
        if evidence.native_errors or evidence.native_skipped_rules or evidence.native_notifications:
            reasons.append("native-issues")
        if evidence.native_execution_successful is not True:
            reasons.append("native-success-not-confirmed")
        if any(item.state != "reported" for item in evidence.files):
            reasons.append("selected-inputs-not-all-reported-without-issue")
    return ResearchExecutionAssessment(
        process_state=state,
        cleanup_succeeded=cleanup_succeeded,
        report_state="reconciled" if evidence is not None else "missing-or-invalid",
        analysis_state="failed" if failed else "incomplete" if reasons else "not-established",
        reasons=tuple(reasons),
    )


def _mount(path: Path, destination: str, *, readonly: bool = True) -> str:
    source = str(path.resolve(strict=True))
    if any(c in source for c in (",", "\r", "\n", "\0")):
        raise ValueError("Unsafe Docker bind source")
    return f"type=bind,source={source},target={destination}" + (",readonly" if readonly else "")


def build_research_argv(
    *,
    docker: Path,
    name: str,
    profile_bytes: bytes,
    scope: SemgrepResearchScope,
    role: Literal["research", "repository-policy"],
    rules: Path,
    target: Path,
    output: Path,
) -> list[str]:
    from agentsec_evidence.core.identity import sha256_bytes

    profile = load_research_profile(profile_bytes)
    scope = SemgrepResearchScope.model_validate(scope.model_dump(mode="json"))
    if scope.profile_sha256 != sha256_bytes(profile_bytes) or not re.fullmatch(
        r"[a-z0-9-]{1,63}", name
    ):
        raise ValueError("Profile identity or container name differs")
    if role not in {"research", "repository-policy"}:
        raise ValueError("Unsupported treatment")
    argv = [
        str(docker),
        "run",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--cpus",
        "2",
        "--memory",
        "2048m",
        "--memory-swap",
        "2048m",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=268435456",
        "--env",
        "HOME=/tmp",
        "--env",
        "SEMGREP_SEND_METRICS=off",
        "--workdir",
        "/src",
        "--mount",
        _mount(rules, "/rules"),
        "--mount",
        _mount(target, "/src"),
        "--mount",
        _mount(output, "/output", readonly=False),
        profile.image,
        "semgrep",
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--jobs=2",
        "--config",
        "/rules/python",
        "--strict",
        "--no-git-ignore",
        "--verbose",
        "--json",
        "--json-output",
        "/output/native.json",
        "--sarif-output",
        "/output/native.sarif",
    ]
    # Explicit targets override ignore-file targeting for the evidence-retaining research pass.
    # Directory discovery applies pinned native policy only to the verified mounted subset.
    return argv + (
        ["--disable-nosem", *["/src/" + e.path for e in scope.selected_files]]
        if role == "research"
        else ["/src"]
    )
