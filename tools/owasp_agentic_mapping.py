"""Offline, proposed OWASP Agentic 2026 relationships over retained corpus reports."""

from __future__ import annotations

import argparse
import html
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from corpus_report_v2 import encoded, manifest_for, read_report
from corpus_sarif import BASELINES, CUSTOM, UNOBSERVED, claim_rows, digest
from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    bounded_file,
    plain_path,
    read_retained_research,
)

CONTRACT = "owasp-agentic-report-overlay-v1"
PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = PROJECT / "profiles/owasp-agentic-2026-mapping-v1.json"
REVIEW = "proposed-not-independently-reviewed"
CATEGORY_TITLES = (
    "Agent Goal Hijack",
    "Tool Misuse and Exploitation",
    "Identity and Privilege Abuse",
    "Agentic Supply Chain Vulnerabilities",
    "Unexpected Code Execution (RCE)",
    "Memory & Context Poisoning",
    "Insecure Inter-Agent Communication",
    "Cascading Failures",
    "Human-Agent Trust Exploitation",
    "Rogue Agents",
)
LIMITATIONS = [
    "Project-proposed relationships, not OWASP endorsement or independently reviewed mappings.",
    "All ten categories remain unassessed as complete security categories; no compliance score.",
    "Related conditions are not verified attacks, runtime effects or confirmed vulnerabilities.",
    "Inventory records are never promoted to findings; ordinary features can be entirely benign.",
    "No relationship does not mean safe, irrelevant or fully analyzed.",
    "Counts are records, not unique issues; repeats, batches and policy views stay separate.",
    "Available native tags stay separate; missing tags, edition and correctness are not inferred.",
    "Input consistency is checked against external hashes; no fresh native replay or attestation.",
    "Excerpts, full native records and prior draft assessments remain in the original evidence.",
]


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Taxonomy(StrictModel):
    name: Literal["OWASP Top 10 for Agentic Applications"]
    edition: Literal["2026"]
    publisher: Literal["OWASP Gen AI Security Project"]
    publication_date: Literal["2025-12-09"]
    checked_date: Literal["2026-10-25"]
    url: Literal["https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"]
    document_url: Literal["https://genai.owasp.org/download/52117/?tmstv=1765059207"]
    document_sha256: Literal["a2db94cd00b08e0b3a5e5b619afe024bdbcd74503111085705e4f3dd886fcb5c"]
    license: Literal["CC-BY-SA-4.0"]
    license_url: Literal["https://creativecommons.org/licenses/by-sa/4.0/"]
    attribution: str = Field(min_length=1, max_length=2000)


class Category(StrictModel):
    id: str
    title: str


class Relationship(StrictModel):
    family: str
    producer: str = Field(min_length=1)
    producer_version: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    record_kind: Literal["condition", "inventory"]
    relationship: Literal["conditional-static-relevance", "inventory-context-only"]
    category: str
    reference_page: int = Field(ge=1, le=56)
    rationale: str = Field(min_length=1, max_length=4000)
    required_verification: str = Field(min_length=1, max_length=4000)
    native_rule: dict[str, Any]

    @model_validator(mode="after")
    def check(self) -> Relationship:
        need(self.family in CUSTOM, "Only custom rule relationships are curated in v1")
        need(self.native_rule.get("rule_id") == self.rule_id, "Rule ID binding differs")
        inventory = self.record_kind == "inventory"
        need(
            self.relationship
            == ("inventory-context-only" if inventory else "conditional-static-relevance"),
            "Inventory cannot become a condition relationship",
        )
        need(
            self.native_rule.get("status", "active-condition")
            == ("inventory-only" if inventory else "active-condition"),
            "Deferred or mismatched rule status",
        )
        return self


class Registry(StrictModel):
    contract: Literal["owasp-agentic-mapping-registry-v1"]
    version: Literal["1.0.0"]
    authorship: Literal["AI-drafted project interpretation"]
    review_status: Literal["proposed-not-independently-reviewed"]
    taxonomy: Taxonomy
    categories: list[Category] = Field(min_length=10, max_length=10)
    mappings: list[Relationship] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def check(self) -> Registry:
        need(
            [(c.id, c.title) for c in self.categories]
            == [(f"ASI{i:02d}", title) for i, title in enumerate(CATEGORY_TITLES, 1)],
            "Wrong or duplicated Agentic 2026 categories",
        )
        keys = [(m.family, m.rule_id) for m in self.mappings]
        need(len(keys) == len(set(keys)), "Duplicate rule relationships")
        need(
            all(m.category in {c.id for c in self.categories} for m in self.mappings),
            "Unknown category",
        )
        return self


def relationship(
    registry: Registry, family: str, info: dict[str, Any], record: dict[str, Any]
) -> dict[str, Any]:
    matches = [m for m in registry.mappings if (m.family, m.rule_id) == (family, record["rule_id"])]
    if not matches:
        return {"status": "unmapped", "reason": "no-curated-project-relationship"}
    mapping = matches[0]
    if (
        mapping.producer != info["tool_name"]
        or mapping.producer_version != info["tool_version"]
        or mapping.native_rule != record["native_rule"]
        or mapping.record_kind != record["record_kind"]
    ):
        return {"status": "unmapped", "reason": "producer-version-rule-or-kind-mismatch"}
    return {
        "status": "proposed-relationship",
        "category": mapping.category,
        "relationship": mapping.relationship,
        "review_status": registry.review_status,
        "rationale": mapping.rationale,
        "required_verification": mapping.required_verification,
        "reference_page": mapping.reference_page,
    }


def inventory_rows(obs: dict[str, Any]) -> list[dict[str, Any]]:
    native = obs["native"]
    rules = {r["rule_id"]: r for r in native["rules"]}
    result = []
    for fi, file in enumerate(native["files"]):
        for ri, record in enumerate(file["inventory"]):
            rid = record.get("rule_id")
            need(rid is None or rid in rules, "Unknown inventory rule ID")
            rule = rules.get(rid)
            need(rule is None or rule.get("status") == "inventory-only", "Inventory rule mismatch")
            result.append(
                {
                    "rule_id": rid,
                    "native_rule": rule,
                    "record_kind": "inventory",
                    "path": file["path"],
                    "span": record["location"],
                    "source_sha256": file["source_sha256"],
                    "native_id": {"blob_sha256": obs["native_sha256"]},
                    "native_pointer": f"/files/{fi}/inventory/{ri}",
                    "native_record_sha256": digest(record),
                    "native_policy": {"policy": native["policy"]},
                }
            )
    return result


def project(report: dict[str, Any], registry: Registry, report_sha: str) -> dict[str, bytes]:
    """Classify retained records, never executable input, and keep repeat-1 accounting separate."""
    need(report.get("contract") == "corpus-core-report-v1", "Unsupported reconstructed report")
    # Repository identity also reaches Markdown; do not allow links or markup through metadata.
    for field, pattern in (
        ("candidate_id", r"R[0-9]{2}"),
        ("repository", r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
        ("revision", r"[0-9a-f]{40}"),
    ):
        value = report["candidate"].get(field)
        need(
            isinstance(value, str) and re.fullmatch(pattern, value) is not None,
            "Invalid repository identity",
        )
    rows, observations = report["rows"], report["observations"]
    need(len({r["key"] for r in rows}) == len(rows), "Duplicate execution cells")
    need(
        {r["key"] for r in rows if r["state"] == "observed"} == set(observations),
        "Observed membership differs",
    )
    files, cells, rule_index = {}, [], {}
    counts: Counter[tuple[str, str]] = Counter()
    for number, row in enumerate(rows, 1):
        family = row["producer"]
        need(family in CUSTOM | BASELINES, "Unknown producer")
        need(type(row["repetition"]) is int and 1 <= row["repetition"] <= 3, "Invalid repetition")
        key = f"runs/r{row['repetition']:02d}/{family}"
        if family in CUSTOM:
            need(type(row["batch"]) is int and row["batch"] >= 0, "Invalid custom batch")
            key += f"/b{row['batch']:03d}"
        else:
            need(row["batch"] is None, "Baseline batches are unsupported")
        need(row["key"] == key, "Execution identity differs")
        cell = {**row, "conditions": None, "inventory": None, "mapped_conditions": None}
        if row["state"] != "observed":
            need(row["state"] in UNOBSERVED, "Unknown execution state")
            need(row["finding_records"] is None, "Unobserved results must remain null")
            cells.append(cell)
            continue
        obs = observations[row["key"]]
        expected_kind = (
            "custom"
            if family in CUSTOM
            else ("semgrep" if family.startswith("semgrep-") else "agent-audit")
        )
        need(obs["kind"] == expected_kind, "Producer/observation kind mismatch")
        claims, info = claim_rows(obs)
        need(row["finding_records"] == len(claims), "Row count differs from observed records")
        records = [{**c, "record_kind": "condition"} for c in claims]
        if obs["kind"] == "custom":
            records.extend(inventory_rows(obs))
            for rule in obs["native"]["rules"]:
                key = (
                    family,
                    info["tool_name"],
                    info["tool_version"],
                    rule["rule_id"],
                    digest(rule),
                )
                status = rule.get("status", "active-condition")
                rule_index[key] = {
                    "family": family,
                    "producer": info["tool_name"],
                    "version": info["tool_version"],
                    "rule_id": rule["rule_id"],
                    "rule_sha256": digest(rule),
                    "native_status": status,
                    "mapping": relationship(
                        registry,
                        family,
                        info,
                        {
                            "rule_id": rule["rule_id"],
                            "native_rule": rule,
                            "record_kind": "inventory"
                            if status == "inventory-only"
                            else "condition",
                        },
                    ),
                }
        mapped = 0
        for record in records:
            record["mapping"] = relationship(registry, family, info, record)
            # Native tags are opaque evidence, never silently upgraded to this taxonomy edition.
            record["native_taxonomy_tags_unreviewed"] = (record.get("native_rule") or {}).get(
                "mappings", []
            )
            record["native_rule_sha256"] = (
                digest(record["native_rule"]) if record.get("native_rule") is not None else None
            )
            record.pop("native_rule", None)
            record.pop("message", None)
            mapping = record["mapping"]
            if mapping["status"] == "proposed-relationship":
                mapped += record["record_kind"] == "condition"
                if row["repetition"] == 1:
                    counts[mapping["category"], record["record_kind"]] += 1
        path = f"cells/{number:04d}.json"
        files[path] = encoded({"cell": row, "producer_context": info, "records": records})
        cell.update(
            conditions=len(claims),
            inventory=len(records) - len(claims) if family in CUSTOM else None,
            mapped_conditions=mapped,
            details=path,
        )
        cells.append(cell)
    categories = []
    for category in registry.categories:
        conditions, inventory = counts[category.id, "condition"], counts[category.id, "inventory"]
        categories.append(
            {
                **category.model_dump(),
                "category_assessment": "not-assessed",
                "related_evidence": "conditional-static-relevance"
                if conditions
                else ("inventory-only" if inventory else "no-related-records"),
                "first_repetition_condition_records": conditions,
                "first_repetition_inventory_records": inventory,
            }
        )
    result = {
        "contract": CONTRACT,
        "candidate": report["candidate"],
        "report_manifest_sha256": report_sha,
        "source_manifest_sha256": report["source_manifest_sha256"],
        "source_content_sha256": report["source_content_sha256"],
        "selection_sha256": report["selection_sha256"],
        "taxonomy": registry.taxonomy.model_dump(),
        "registry_version": registry.version,
        "mapping_authorship": registry.authorship,
        "mapping_review_status": registry.review_status,
        "summary_basis": "first-repetition-only; observations-not-unique-vulnerabilities",
        "categories": categories,
        "cells": cells,
        "custom_rule_accounting": [rule_index[k] for k in sorted(rule_index)],
        "scanner_invocations": 0,
        "native_replay": False,
        "human_acceptance": False,
        "distribution": "internal-unredacted; separate release review required",
        "limitations": LIMITATIONS,
    }
    files["mapping.json"] = encoded(result)
    files["README.md"] = markdown(result).encode()
    return files


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# OWASP Agentic 2026 Mapping",
        "",
        "Additive offline interpretation. No new scans or vulnerability confirmations.",
        "",
        "Repository: " + html.escape(result["candidate"]["repository"]),
        "Revision: " + html.escape(result["candidate"]["revision"]),
        "",
        "Categories remain **not assessed in full**. Counts indicate related evidence only.",
        "Only repetition 1 is counted; all repetitions and views remain in cells/*.json.",
        "A zero is no related record in this limited mapping, not a passed security check.",
        "",
        "| Category | Title | Related conditions | Inventory only |",
        "|---|---|---:|---:|",
    ]
    lines.extend(
        f"| {c['id']} | {c['title']} | {c['first_repetition_condition_records']} | "
        f"{c['first_repetition_inventory_records']} |"
        for c in result["categories"]
    )
    lines += [
        "",
        "## Evidence and Limits",
        "",
        *["- " + s for s in LIMITATIONS],
        "",
        "See mapping.json for execution states and custom rule status; cells/*.json for",
        "per-record identities, source paths, proposed relationships and verification needs.",
        "Unmapped records retain their original identities and explicit reasons.",
        "",
        "Registry: registry.json. Provenance: provenance.json. Input reports remain external.",
        "The copied registry records source attribution, edition and reference PDF hash.",
        "",
    ]
    return "\n".join(lines)


def execute(
    mode: str, report: Path, report_sha256: str, registry: Path, registry_sha256: str, output: Path
) -> dict[str, Any]:
    need(mode in {"write", "verify"}, "Unknown mode")
    root = plain_path(report, directory=True)
    registry = plain_path(registry, directory=False)
    output = Path(os.path.abspath(output))
    for source in (root, registry):
        need(
            not output.is_relative_to(source) and not source.is_relative_to(output),
            "Output overlaps source evidence or registry",
        )
    if output.is_relative_to(PROJECT):
        need(
            any(output.is_relative_to(PROJECT / p) for p in ("outputs", "workspace")),
            "Project output must be under outputs or workspace, not source directories",
        )
    manifest_raw = bounded_file(root / "evidence-manifest.json", MAX_ENTRY_BYTES)
    need(sha256_bytes(manifest_raw) == report_sha256, "External report hash differs")
    raw = bounded_file(registry, 256 * 1024)
    need(sha256_bytes(raw) == registry_sha256, "External registry hash differs")
    model = Registry.model_validate(load_agent_json(raw, max_bytes=256 * 1024))
    projection = read_report(root)
    need(
        sha256_bytes(bounded_file(root / "evidence-manifest.json", MAX_ENTRY_BYTES))
        == report_sha256,
        "Report changed during read",
    )
    files = project(projection, model, report_sha256)
    files["registry.json"] = raw
    files["source-evidence-manifest.json"] = manifest_raw
    files["provenance.json"] = encoded(
        {
            "contract": CONTRACT,
            "report_manifest_sha256": report_sha256,
            "registry_sha256": registry_sha256,
            "implementation_sha256": sha256_bytes(bounded_file(Path(__file__), MAX_ENTRY_BYTES)),
            "helpers": {
                p: sha256_bytes(bounded_file(PROJECT / p, MAX_ENTRY_BYTES))
                for p in (
                    "tools/corpus_report_v2.py",
                    "tools/corpus_sarif.py",
                    "src/agentsec_evidence/research/retained.py",
                )
            },
            "offline": True,
            "scanner_invocations": 0,
            "native_replay": False,
            "reference_pdf_used_at_runtime": False,
            "independent_attestation": False,
        }
    )
    manifest = manifest_for(files)
    if mode == "write":
        plain_path(output.parent, directory=True)
        need(not output.exists(), "Use a fresh mapping output directory")
        output.mkdir()
        for name, content in files.items():
            atomic_write_bytes(output / name, content)
        save(output / "evidence-manifest.json", manifest)
    need(not (output / "runtime").exists(), "Unexpected runtime directory in mapping package")
    need(read_retained_research(output).files == files, "Mapping differs from bound projection")
    return {
        "contract": CONTRACT,
        "passed": True,
        "files": len(files),
        "report_manifest_sha256": report_sha256,
        "registry_sha256": registry_sha256,
        "mapping_review_status": REVIEW,
        "scanner_invocations": 0,
        "native_replay": False,
        "human_acceptance": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument(
        "--report", type=Path, required=True, help="Sealed corpus-core-report-v2 folder"
    )
    parser.add_argument(
        "--report-sha256", required=True, help="External evidence-manifest.json hash"
    )
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--registry-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    print(encoded(execute(**vars(parser.parse_args()))).decode())


if __name__ == "__main__":
    main()
