"""Offline replay of sealed, finite custom-rule repair bundles; never execute their code."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue, TypeAdapter

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.models.contracts import InventoryEntry, Sha256
from agentsec_evidence.reporting.custom_contracts import (
    BY_VERIFICATION,
    IMAGE,
    NATIVE,
    TREATMENTS,
    CustomSummary,
    CustomTreatment,
    Family,
)
from agentsec_evidence.reporting.custom_export import custom_sarif_runs
from agentsec_evidence.reporting.custom_models import CustomSource
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    MAX_TREE_BYTES,
    RetainedResearch,
    bounded_file,
    plain_path,
)

_HASH_MAP = TypeAdapter(dict[str, Sha256])
_CONTROLS = {
    "tool-execution": {"corrected-literal-parser", "tool-corrected", "shell-false", "fixed-import"},
    "network-data": {"fixed-http", "fixed-tool", "auth-header-not-leak", "fixed-s3", "fixed-proxy"},
    "filesystem": {
        "fixed-read",
        "fixed-write",
        "copy-fixed",
        "fixed-helper",
        "fixed-agent-tool",
        "safe-yaml-loader",
    },
    "memory-state": {
        "literal-canary",
        "literal-logging",
        "fixed-http-body",
        "system-mapping-fixed",
        "system-message-fixed",
        "plain-source",
    },
    "self-modification": {
        "fixed-prompt",
        "fixed-addition",
        "fixed-eval",
        "safe-response-parser",
        "ordinary-validation",
        "plain-source",
    },
    "orchestration": {
        "fixed-handoff",
        "fixed-route",
        "fixed-state",
        "ordinary-helper",
        "comment-only",
        "plain-source",
    },
    "agent-to-agent": {
        "fixed-call",
        "fixed-verify",
        "fixed-update",
        "ordinary-helper",
        "comment-only",
        "plain-source",
    },
}


def _read(root: Path) -> RetainedResearch:
    root = plain_path(root, directory=True)
    raw = bounded_file(root / "manifest.json", 4 * 1024**2)
    manifest = _HASH_MAP.validate_python(load_agent_json(raw, max_bytes=4 * 1024**2))
    if not 1 <= len(manifest) <= 4096 or "manifest.json" in manifest:
        raise ValueError("Invalid repair evidence manifest")
    allowed_dirs: set[str] = set()
    for path in manifest:
        canonical_artifact_path(path)
        if len(path.split("/")) > 64:
            raise ValueError("Repair evidence path depth exceeded")
        allowed_dirs.update(p.as_posix() for p in Path(path).parents if p.as_posix() != ".")
    if len({name.casefold() for name in manifest}) != len(manifest):
        raise ValueError("Case-colliding repair evidence names")
    actual: set[str] = set()
    for directory, dirs, names in os.walk(root):
        for name in dirs:
            directory_path = Path(directory) / name
            plain_path(directory_path, directory=True)
            if directory_path.relative_to(root).as_posix() not in allowed_dirs:
                raise ValueError("Unmanifested repair directory")
        for name in names:
            relative = (Path(directory) / name).relative_to(root).as_posix()
            if relative != "manifest.json":
                actual.add(relative)
                if relative not in manifest:
                    raise ValueError("Unmanifested repair evidence")
    if actual != set(manifest):
        raise ValueError("Repair evidence membership differs")
    files: dict[str, bytes] = {}
    total = 0
    for path, digest in manifest.items():
        data = bounded_file(root / path, MAX_ENTRY_BYTES)
        total += len(data)
        if total > MAX_TREE_BYTES or sha256_bytes(data) != digest:
            raise ValueError("Repair evidence size or hash differs")
        files[path] = data
    return RetainedResearch(root, sha256_bytes(raw), files)


def _json(evidence: RetainedResearch, path: str) -> dict[str, Any]:
    return cast(dict[str, Any], load_agent_json(evidence.read(path), max_bytes=MAX_ENTRY_BYTES))


def _command(argv: list[str], family: Family, treatment: str) -> None:
    expected = [
        "docker",
        "run",
        "--name",
        "<container>",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--workdir",
        "/tmp",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONPATH=/app/src",
        "--mount",
        "type=bind,src=<source>,dst=/app/src,readonly",
        "--mount",
        "type=bind,src=<target>,dst=/target,readonly",
        "--mount",
        "type=bind,src=<request>,dst=/request.json,readonly",
        IMAGE,
        "/app/.venv/bin/python",
        "-P",
        "-X",
        "utf8",
        "-m",
        "agentsec_evidence.custom_rules." + family.worker,
        "/request.json",
        "/target",
        "--fail-on",
        family.threshold,
    ]
    if len(argv) != len(expected) or not all(isinstance(value, str) for value in argv):
        raise ValueError("Unexpected repaired-worker command")
    normalized = list(argv)
    if not argv[3] or not argv[3].endswith("-" + treatment):
        raise ValueError("Missing treatment-bound container name")
    normalized[3] = "<container>"
    roots = []
    for marker, suffix in (
        ("<source>", "source-snapshot/src"),
        ("<target>", "input"),
        ("<request>", treatment + "/request.json"),
    ):
        index = next(i for i, value in enumerate(expected) if f"src={marker}," in value)
        value = argv[index]
        before, after = expected[index].split(marker)
        if not value.startswith(before) or not value.endswith(after):
            raise ValueError("Changed repair bind mount or isolation policy")
        host = value[len(before) : -len(after)].replace("\\", "/")
        if not host.endswith("/" + suffix):
            raise ValueError("Repair mount does not bind expected evidence layout")
        roots.append(host[: -len(suffix)])
        normalized[index] = expected[index]
    if len(set(roots)) != 1 or normalized != expected:
        raise ValueError("Changed repair command or inconsistent mount roots")


def load_custom_source(project: Path, root: Path) -> tuple[CustomSource, dict[str, JsonValue]]:
    try:
        return _load_custom_source(project, root)
    except (KeyError, TypeError, IndexError, AttributeError, StopIteration) as error:
        raise ValueError("Malformed custom repair evidence") from error


def _load_custom_source(project: Path, root: Path) -> tuple[CustomSource, dict[str, JsonValue]]:
    evidence = _read(root)
    verification = _json(evidence, "verification.json")
    family = BY_VERIFICATION.get(str(verification.get("contract")))
    if family is None:
        raise ValueError("Unsupported repaired-worker evidence contract")
    implementation = _HASH_MAP.validate_python(_json(evidence, "implementation.json"))
    for path, digest in implementation.items():
        canonical_artifact_path(path)
        if sha256_bytes(evidence.read("source-snapshot/" + path)) != digest:
            raise ValueError("Frozen repair implementation differs")
    required = family.critical_sources | {family.registry, "tools/" + family.helper}
    for path in required:
        if path not in implementation or sha256_file(project / path) != implementation[path]:
            raise ValueError("Unsupported or changed repair implementation/registry pin: " + path)
    registry_bytes = evidence.read("source-snapshot/" + family.registry)
    registry = cast(dict[str, Any], load_agent_json(registry_bytes, max_bytes=MAX_ENTRY_BYTES))
    if (
        registry.get("contract") != family.key + "-repair-cases-v1"
        or verification.get("registry_sha256") != sha256_bytes(registry_bytes)
        or verification.get("image_id") != IMAGE
        or verification.get("repeated_native_bytes_equal") is not True
        or verification.get("case_count") != len(registry["cases"])
    ):
        raise ValueError("Repair registry or verification identity differs")
    inputs = {f"{case['id']}.py": case["source"].encode() for case in registry["cases"]}
    inventory = [
        InventoryEntry(
            path=name, sha256=sha256_bytes(data), byte_length=len(data), media_type="text/x-python"
        )
        for name, data in sorted(inputs.items())
    ]
    for name, data in inputs.items():
        if evidence.read("input/" + name) != data:
            raise ValueError("Retained repair input differs from frozen authored registry")
    expected_paths = {
        "verification.json",
        "implementation.json",
        "image-inspect.stdout.json",
        "image-inspect.stderr.txt",
        *("source-snapshot/" + path for path in implementation),
        *("input/" + path for path in inputs),
        *(
            f"{key}/{name}"
            for key in TREATMENTS
            for name in (
                "request.json",
                "invocation.json",
                "process.json",
                "stdout.json",
                "stderr.txt",
            )
        ),
    }
    if set(evidence.files) != expected_paths or evidence.read("image-inspect.stderr.txt"):
        raise ValueError("Unexpected repair evidence layout or image-inspection failure")
    images = load_agent_json(
        b'{"images":' + evidence.read("image-inspect.stdout.json") + b"}",
        max_bytes=MAX_ENTRY_BYTES + 32,
    )["images"]
    if (
        not isinstance(images, list)
        or len(images) != 1
        or not isinstance(images[0], dict)
        or images[0].get("Id") != IMAGE
    ):
        raise ValueError("Retained image identity differs")
    rows = verification["rows"]
    if [row["treatment"] for row in rows] != list(TREATMENTS):
        raise ValueError("Repair verification treatment order differs")
    treatments: list[CustomTreatment] = []
    for key, row in zip(TREATMENTS, rows, strict=True):
        request_bytes = evidence.read(f"{key}/request.json")
        request = AgentInputRequest.model_validate(
            load_agent_json(request_bytes, max_bytes=256 * 1024)
        )
        selected = set(inputs)
        if key == "valid-only":
            selected = {
                f"{case['id']}.py" for case in registry["cases"] if case["rules"] is not None
            }
        elif key == "corrected-controls":
            selected = {name + ".py" for name in _CONTROLS[family.key]}
        if (
            request.target_snapshot_id != "development-" + family.key + "-v1"
            or request.inventory != inventory
            or request.selected != {path: "python-source" for path in selected}
        ):
            raise ValueError("Retained repair input selection differs from its finite treatment")
        raw = evidence.read(f"{key}/stdout.json")
        native = NATIVE.validate_python(load_agent_json(raw, max_bytes=MAX_ENTRY_BYTES))
        if native.contract != family.contract or native.request_sha256 != sha256_bytes(
            request_bytes
        ):
            raise ValueError("Repaired native report or exact request binding differs")
        for file in native.files:
            lines = inputs[file.path].splitlines()
            for item in [*(file.findings or []), *file.inventory, *file.limitations_observed]:
                span = cast(Any, item).location
                if (span.end_line, span.end_utf8_byte_column) < (
                    span.start_line,
                    span.start_utf8_byte_column,
                ) or span.end_line > len(lines):
                    raise ValueError("Native source range is outside the input")
                for line, column in (
                    (span.start_line, span.start_utf8_byte_column),
                    (span.end_line, span.end_utf8_byte_column),
                ):
                    if column > len(lines[line - 1]):
                        raise ValueError("Native column is outside the source line")
                    lines[line - 1][:column].decode("utf-8", errors="strict")
        process = _json(evidence, f"{key}/process.json")
        invocation = _json(evidence, f"{key}/invocation.json")
        if set(process) != {"exit_code", "duration_ns"} or set(invocation) != {
            "argv",
            "expected_exit",
        }:
            raise ValueError("Unexpected repair process receipt")
        _command(invocation["argv"], family, key)
        treatment = CustomTreatment(
            key=key,
            request=request,
            native=native,
            request_json=request_bytes.decode("utf-8"),
            native_json=raw.decode("utf-8"),
            stdout_sha256=sha256_bytes(raw),
            invocation_sha256=sha256_bytes(evidence.read(f"{key}/invocation.json")),
            duration_ns=process["duration_ns"],
            exit_code=process["exit_code"],
        )
        facts = {
            "treatment": key,
            "selected_files": len(native.files),
            "execution_state": native.execution_state,
            "native_findings": sum(len(file.findings or []) for file in native.files),
            "files_with_unknown_or_unsupported_constructs": sum(
                bool(file.limitations_observed) for file in native.files
            ),
            "exit_code": treatment.exit_code,
            "duration_ns": treatment.duration_ns,
            "stdout_sha256": treatment.stdout_sha256,
        }
        if family.key != "tool-execution":
            facts["inventory_rule_observations"] = sum(
                getattr(item, "rule_id", None) is not None
                for file in native.files
                for item in file.inventory
            )
        if (
            row != facts
            or invocation["expected_exit"] != treatment.exit_code
            or evidence.read(f"{key}/stderr.txt")
        ):
            raise ValueError("Repair verification counters or process status disagree")
        treatments.append(treatment)
    summary = CustomSummary(
        family=family.key,
        registry_sha256=sha256_bytes(registry_bytes),
        implementation_sha256=sha256_bytes(evidence.read("implementation.json")),
        treatments=tuple(treatments),
    )
    source = CustomSource(
        run_id="custom-repair-" + semantic_hash({"manifest": evidence.manifest_sha256})[:32],
        state="partial"
        if any(t.native.execution_state != "complete" for t in treatments)
        else "complete",
        label="Development repair: " + family.key,
        revision="1.0.0",
        source_manifest_sha256=evidence.manifest_sha256,
        summary=summary,
    )
    return source, {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": cast(list[JsonValue], custom_sarif_runs(source)),
    }
