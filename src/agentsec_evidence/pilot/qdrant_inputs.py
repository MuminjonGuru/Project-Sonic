"""The finite Qdrant admission; deliberately not an unrestricted repository runner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.view_validation import build_agent_view_request
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.intake.git_verification import GitSourceVerification
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.repository import (
    load_intake_spec,
    prepare_repository,
    verify_repository,
)
from agentsec_evidence.intake.views import (
    ToolInputView,
    ToolViewContext,
    expected_tool_view,
    materialize_tool_view,
    verify_materialized_tool_view,
)
from agentsec_evidence.pilot.inputs import LIMITS_PATH, PROFILE_PATH, TOOL_PATH
from agentsec_evidence.pilot.runner import load, save
from agentsec_evidence.research.inputs import (
    ResearchPreparation,
    materialize_research_inputs,
    prepare_research_inputs,
    replay_research_inputs,
    research_mount_context,
    research_worker_request,
)
from agentsec_evidence.research.models import load_research_profile, verify_rule_bytes
from agentsec_evidence.research.retained import bounded_file

REPOSITORY = "https://github.com/qdrant/mcp-server-qdrant"
REVISION = "c56ae5adf62bb78d852bf7bbcbc5d7b75e2bbe41"
CONTENT = "87b68f245c413e2b5e920fe4e958345a9102fd9a480391f8ad40ad507f11c71f"
DATABASE = "6f7b248e44eeadbf0d669c2e2842adc19bc1929f1b9da8ae2e69991dab3cbbdd"
LOCKFILE = "a9d200c4372a3fae82c4c43a849edc75cb54a33eddb59ffce828e29f11499304"
SPEC = "test_cases/pilot/qdrant-mcp/intake-spec.json"
MCP = "kiro-power/mcp.json"
PINS = {
    PROFILE_PATH: "ce4b8517a4042bb247ac641250f5d9428e8a5f985db69d36f2d9fef28f09e23c",
    TOOL_PATH: "0cbc071b465e1f8a965df3419042f52aee6e6f592668a5fd4c1426f12590313a",
    LIMITS_PATH: "d8ee765569cde2f87107ace4ddd04f64c3cccd253af462f04bff4f934df1aa6c",
    "configs/dependency/tools.json": (
        "176c2099bc13a2c7d120c27ca014e91808bbcaba58bfa017d79b7e84cd6b8f96"
    ),
    "configs/dependency/osv.toml": (
        "0ce7ce124bbe33592a7d166230971e220f7f59177b6b0e295983fe7506757871"
    ),
    "configs/dependency/syft.yaml": (
        "aff991297d3b515fe9fb0a8467cc26c3a419421aa0c5bdc61e74422ca84c18d7"
    ),
    "uv.lock": "b072464773b77a68d6f03345f6f913568773903671821eb6b61d4ea312fcfb6c",
}


def bind(path: Path, value: Any, *, write: bool) -> None:
    """Persist once, or compare a derivative with a freshly rebuilt value on replay."""
    if write:
        save(path, value)
    elif load(path, 16 * 1024**2) != value:
        raise ValueError("Retained derivative differs: " + str(path))


def verify_pins(root: Path) -> None:
    for name, digest in PINS.items():
        if sha256_file(root / name) != digest:
            raise ValueError("Approved configuration pin changed: " + name)


def equivalent_python_requests(left: AgentInputRequest, right: AgentInputRequest) -> bool:
    # Sequence order is serialization evidence, not a difference in selected file content.
    return (
        left.target_snapshot_id == right.target_snapshot_id
        and left.selected == right.selected
        and {item.path: item for item in left.inventory}
        == {item.path: item for item in right.inventory}
    )


@dataclass(frozen=True)
class QdrantInputs:
    root: Path
    contexts: dict[str, ToolViewContext]
    views: dict[str, ToolInputView]
    requests: dict[str, AgentInputRequest]
    research: ResearchPreparation

    @property
    def source(self) -> Path:
        return self.root / "preparation/source"


def prepare_qdrant(
    project: Path, output: Path, *, cache: Path, rules: Path, database: Path
) -> QdrantInputs:
    verify_pins(project)
    if sha256_file(database) != DATABASE:
        raise ValueError("Frozen PyPI database differs")
    for name in (*PINS, SPEC):
        atomic_write_bytes(output / "frozen" / name, bounded_file(project / name, 2 * 1024**2))
    profile = load_research_profile((project / PROFILE_PATH).read_bytes())
    raw_rules = {
        r.source_path: bounded_file(rules / r.source_path, 256 * 1024) for r in profile.rules
    }
    license_bytes = bounded_file(rules / "LICENSE", 256 * 1024)
    verify_rule_bytes(profile, raw_rules, license_bytes=license_bytes)
    for name, raw in {**raw_rules, "LICENSE": license_bytes}.items():
        atomic_write_bytes(output / "rules" / name, raw)
    spec = load_intake_spec(output / "frozen" / SPEC)
    if spec.source_label != REPOSITORY or spec.revision != REVISION:
        raise ValueError("Target is outside the Qdrant admission")
    prepare_repository(spec, cache=cache, output=output / "preparation")
    return replay_qdrant_inputs(output, write=True)


def replay_qdrant_inputs(root: Path, *, write: bool = False) -> QdrantInputs:
    frozen = root / "frozen"
    verify_pins(frozen)
    spec = load_intake_spec(frozen / SPEC)
    receipt = verify_repository(root / "preparation", spec=spec)
    if (
        spec.source_label != REPOSITORY
        or spec.revision != REVISION
        or receipt.source_content_sha256 != CONTENT
        or receipt.observed_files != 34
        or receipt.observed_bytes != 539332
    ):
        raise ValueError("Source differs from the approved finite repository")
    base = root / "preparation"
    inventory = ArtifactInventory.model_validate_json(
        (base / "artifact-inventory.json").read_bytes()
    )
    proof = GitSourceVerification.model_validate_json((base / "git-verification.json").read_bytes())
    paths = [f.source.path for f in proof.files]
    python_paths = sorted(p for p in paths if p.endswith(".py"))
    if len(python_paths) != 19 or MCP not in paths:
        raise ValueError("Python/MCP selection differs")
    source = base / "source"
    if sha256_file(source / "uv.lock") != LOCKFILE:
        raise ValueError("Dependency input differs")
    profile_bytes = (frozen / PROFILE_PATH).read_bytes()
    profile = load_research_profile(profile_bytes)
    verify_rule_bytes(
        profile,
        {
            r.source_path: bounded_file(root / "rules" / r.source_path, 256 * 1024)
            for r in profile.rules
        },
        license_bytes=bounded_file(root / "rules/LICENSE", 256 * 1024),
    )
    contexts = {}
    views = {}
    requests = {}
    for name, tool, selected, raw, profile_id in (
        ("semgrep", "semgrep", python_paths, profile_bytes, profile.profile_id),
        (
            "agent-python",
            "agent-audit",
            python_paths,
            (frozen / TOOL_PATH).read_bytes(),
            "python-source-pilot-v1",
        ),
        (
            "agent-mcp",
            "agent-audit",
            [MCP],
            (frozen / TOOL_PATH).read_bytes(),
            "qdrant-local-mcp-static-v1",
        ),
    ):
        plan = build_tool_input_plan(
            inventory=inventory,
            verification=proof,
            tool_id=tool,
            profile_id=profile_id,
            profile_bytes=raw,
            selected_paths=selected,
            selected_reason="P4-D-2026-10-18-03: bounded Qdrant static treatment",
            exclusions={
                p: "Outside this treatment; retained in parent inventory"
                for p in paths
                if p not in selected
            },
        )
        bind(root / (name + "-input-plan.json"), plan.model_dump(mode="json"), write=write)
        context = ToolViewContext(
            inventory,
            proof,
            plan,
            raw,
            (base / "raw/commit.bin").read_bytes(),
            (base / "raw/tree-exact.json").read_bytes(),
        )
        contexts[name] = context
        if name == "semgrep":
            if write:
                research, view = materialize_research_inputs(
                    context, source=source, output=root / "semgrep-view"
                )
            else:
                research = prepare_research_inputs(context, source)
                view = expected_tool_view(research_mount_context(context, research))
            if research.scope is None or view is None:
                raise ValueError("Semgrep policy refused; scanners not authorized")
            replay_research_inputs(
                context,
                source=source,
                preparation=research,
                view=view,
                target=root / "semgrep-view/target",
            )
            bind(root / "semgrep-policy.json", research.policy.model_dump(mode="json"), write=write)
            bind(root / "semgrep-scope.json", research.scope.model_dump(mode="json"), write=write)
            request = research_worker_request(research.scope)
        else:
            view = (
                materialize_tool_view(context, source_root=source, output=root / (name + "-view"))
                if write
                else expected_tool_view(context)
            )
            verify_materialized_tool_view(view, context, root / (name + "-view/target"))
            request = build_agent_view_request(
                context,
                view,
                selected_kinds={
                    p: "python-source" if name == "agent-python" else "mcp-config" for p in selected
                },
            )
        bind(root / (name + "-request.json"), request.model_dump(mode="json"), write=write)
        views[name], requests[name] = view, request
    if not equivalent_python_requests(requests["semgrep"], requests["agent-python"]):
        raise ValueError("Python treatments selected different inputs")
    admission = {
        "contract": "dependency-pilot-admission-v1",
        "status": "approved",
        "approval_kind": "P4-D-2026-10-18-03: student-approved formative pilot",
        "repository": REPOSITORY,
        "revision": REVISION,
        "content_sha256": CONTENT,
        "lockfile_sha256": LOCKFILE,
        "database_sha256": DATABASE,
        "eligible_unique_identities": 111,
        "oracle_review": "student-confirmed",
        "oracle_review_scope": "Previously approved finite fixture only; no public oracle.",
        "scope": "Lockfile-wide PyPI, all markers/groups; local root separate; no installation",
    }
    bind(root / "dependency-admission.json", admission, write=write)
    return QdrantInputs(root, contexts, views, requests, research)
