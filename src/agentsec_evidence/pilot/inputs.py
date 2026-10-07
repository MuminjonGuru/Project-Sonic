from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.view_validation import build_agent_view_request
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model
from agentsec_evidence.intake.git_verification import GitSourceVerification
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.source_preparation import SourcePreparationSpec, prepare_cached_source
from agentsec_evidence.intake.views import (
    ToolInputView,
    ToolViewContext,
    materialize_tool_view,
    replay_parent_source,
    verify_materialized_tool_view,
)
from agentsec_evidence.pilot.models import PilotPlan
from agentsec_evidence.research.inputs import (
    ResearchPreparation,
    materialize_research_inputs,
    replay_research_inputs,
    research_worker_request,
)
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.retained import bounded_file, plain_path

PLAN_PATH = "test_cases/pilot/langgraph-cicd/source-pilot.json"
PROFILE_PATH = "configs/research/semgrep-python-candidate-v1.json"
TOOL_PATH = "configs/tools/agent-audit-pilot.toml"
LIMITS_PATH = "configs/profiles/source-pilot.toml"
SPEC_PATH = "test_cases/pilot/langgraph-cicd/source-preparation.json"
ADMISSION_PATH = "test_cases/pilot/langgraph-cicd/admission.json"
PIN_PATHS = frozenset(
    (
        PROFILE_PATH,
        TOOL_PATH,
        LIMITS_PATH,
        SPEC_PATH,
        ADMISSION_PATH,
        "uv.lock",
        "configs/dependency/tools.json",
        "configs/dependency/osv.toml",
        "configs/dependency/syft.yaml",
    )
)


def load_plan(project: Path) -> PilotPlan:
    plan = PilotPlan.model_validate_json(bounded_file(project / PLAN_PATH, 128 * 1024))
    if set(plan.pins) != PIN_PATHS:
        raise ValueError("Pilot pin set differs")
    for path, expected in plan.pins.items():
        if sha256_bytes(bounded_file(project / path, 2 * 1024 * 1024)) != expected:
            raise ValueError("Pilot configuration changed: " + path)
    return plan


@dataclass(frozen=True)
class PilotInputs:
    root: Path
    source: Path
    plan: PilotPlan
    semgrep: ToolViewContext
    agent: ToolViewContext
    preparation: ResearchPreparation
    semgrep_view: ToolInputView
    agent_view: ToolInputView
    request: AgentInputRequest
    database: Path

    def replay(self) -> None:
        replay_research_inputs(
            self.semgrep,
            source=self.source,
            preparation=self.preparation,
            view=self.semgrep_view,
            target=self.root / "semgrep-view/target",
        )
        replay_parent_source(self.agent, self.source)
        verify_materialized_tool_view(self.agent_view, self.agent, self.root / "agent-view/target")
        if sha256_file(self.database) != self.plan.database_sha256:
            raise ValueError("Frozen database changed")


def prepare_pilot_inputs(
    project: Path,
    output: Path,
    *,
    cache: Path,
    rule_source: Path,
    database: Path,
) -> PilotInputs:
    plan = load_plan(project)
    database = plain_path(database, directory=False)
    if sha256_file(database) != plan.database_sha256:
        raise ValueError("Pilot requires the existing frozen database")
    for path in (*plan.pins, PLAN_PATH):
        atomic_write_bytes(output / "frozen" / path, (project / path).read_bytes())
    profile_bytes = (project / PROFILE_PATH).read_bytes()
    profile = load_research_profile(profile_bytes)
    rules = {
        r.source_path: bounded_file(rule_source / r.source_path, MAX_FILE_BYTES)
        for r in profile.rules
    }
    license_bytes = bounded_file(rule_source / "LICENSE", MAX_FILE_BYTES)
    verify_rule_bytes(profile, rules, license_bytes=license_bytes)
    for path, raw in {**rules, "LICENSE": license_bytes}.items():
        atomic_write_bytes(output / "rules" / path, raw)
    spec = SourcePreparationSpec.model_validate_json((project / SPEC_PATH).read_bytes())
    receipt = prepare_cached_source(spec, cache=cache, output=output / "preparation")
    if receipt.get("passed") is not True:
        raise ValueError("Source preparation did not pass")
    base = output / "preparation"
    inventory = ArtifactInventory.model_validate_json(
        (base / "artifact-inventory.json").read_bytes()
    )
    proof = GitSourceVerification.model_validate_json((base / "git-verification.json").read_bytes())
    if (
        proof.revision != plan.revision
        or inventory.snapshot.content_sha256 != plan.content_sha256
        or len(proof.files) != plan.expected_files
        or tuple(f.source.path for f in proof.files if f.source.path.endswith(".py"))
        != plan.python_paths
    ):
        raise ValueError("Prepared repository differs from approved pilot scope")
    contexts = []
    for tool, raw, profile_id in (
        ("semgrep", profile_bytes, profile.profile_id),
        ("agent-audit", (project / TOOL_PATH).read_bytes(), "python-source-pilot-v1"),
    ):
        selection = build_tool_input_plan(
            inventory=inventory,
            verification=proof,
            tool_id=tool,
            profile_id=profile_id,
            profile_bytes=raw,
            selected_paths=list(plan.python_paths),
            selected_reason="Student-approved all-Python pilot view; retain test/example/CI roles",
            exclusions={
                f.source.path: "Not Python; retained in full inventory and separate tool scope"
                for f in proof.files
                if f.source.path not in plan.python_paths
            },
        )
        atomic_write_model(output / f"{tool}-input-plan.json", selection)
        contexts.append(
            ToolViewContext(
                inventory,
                proof,
                selection,
                raw,
                (base / "raw/commit.bin").read_bytes(),
                (base / "raw/tree-exact.json").read_bytes(),
            )
        )
    semgrep, agent = contexts
    source = base / "source"
    preparation, semgrep_view = materialize_research_inputs(
        semgrep, source=source, output=output / "semgrep-view"
    )
    atomic_write_model(output / "semgrep-policy.json", preparation.policy)
    if preparation.scope is None or semgrep_view is None:
        raise ValueError("Public input refused by Semgrep policy gate; no scanner launched")
    atomic_write_model(output / "semgrep-scope.json", preparation.scope)
    agent_view = materialize_tool_view(agent, source_root=source, output=output / "agent-view")
    request = build_agent_view_request(
        agent, agent_view, selected_kinds={p: "python-source" for p in plan.python_paths}
    )
    if request != research_worker_request(preparation.scope):
        raise ValueError("Treatments must nominate identical validated Python inputs")
    atomic_write_model(output / "request.json", request)
    result = PilotInputs(
        output,
        source,
        plan,
        semgrep,
        agent,
        preparation,
        semgrep_view,
        agent_view,
        request,
        database,
    )
    result.replay()
    return result
