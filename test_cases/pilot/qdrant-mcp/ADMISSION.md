# Qdrant MCP: Bounded Pilot Admission

**Date:** 18 October 2026. **Authority:** student selected "Approve this bounded Qdrant pilot".
**Role:** formative pilot, permanently excluded from held-out evaluation.
**Status:** scope approved; source preparation and isolated input preflight passed locally.
The separately versioned security-execution/reporting workflow is not implemented by this record.
This is not academic approval, a vulnerability oracle, public-release clearance or an executable
plan accepted by the historical one-repository runner.

## Source

- Repository: <https://github.com/qdrant/mcp-server-qdrant>.
- Revision: `c56ae5adf62bb78d852bf7bbcbc5d7b75e2bbe41`.
- Root tree: `dc6a6cfc205a379273aa92d5de841f126e32b161`.
- Full inventory: 34 regular files, 539,332 bytes, including tests, CI, documentation and policy.
- Source-content SHA-256: `87b68f245c413e2b5e920fe4e958345a9102fd9a480391f8ad40ad507f11c71f`.
- Intake specification: [intake-spec.json](intake-spec.json). Its `not-granted` value is deliberate:
  preparation never grants scanning; this separate record approves only the bounded treatment.
- License observation: pinned `LICENSE` identifies Apache-2.0; original remains in private evidence.
  License-file SHA-256: `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
  Third-party files/native evidence are not distributed by this admission.

## Approved Treatment

| Stage | Exact input | Treatment |
|---|---|---|
| Semgrep research | All 19 `.py` files, including four under `tests/` | Existing unchanged 68-rule GitLab Python profile; research coverage view |
| Semgrep policy | Same 19 nominated files | Existing repository-policy view; implicit Git-ignore filtering remains disabled; native default ignores remain observable |
| Agent Audit Python | Same 19 Python files | Existing pinned static analyzer; preserve native assertions and unknown per-file analysis completeness |
| Agent Audit MCP | `kiro-power/mcp.json` only | Actual local `mcpServers` declaration; separate selected view and results from Python |
| OSV direct | Root `uv.lock` only | Existing strict-offline matching, shared explicit config and frozen PyPI data |
| Syft then OSV SBOM | Same root `uv.lock` | Existing single Syft native JSON/CycloneDX 1.6 generation, followed by offline OSV |

Three fresh sequential repetitions are approved. No rule/model/database refresh, installation,
target import, target tests, server startup, Qdrant endpoint access, embedding download, shell
command from target content, environment-placeholder expansion or live-agent operation.
Use existing read-only/non-root/network-denied/resource-bounded containers. Retain every attempt;
no automatic retry or treatment change. Keep an eligible repository with zero findings.

Lockfile format 1 declares 112 entries: 111 eligible PyPI name/version pairs and one separate
local `mcp-server-qdrant` 0.8.1 root. No unsupported or source-ambiguous projections were reported
by the existing declaration parser. These are input observations, not scanner results, a complete
installed graph, independent ground truth or proof that every package is matched.
Lockfile SHA-256: `a9d200c4372a3fae82c4c43a849edc75cb54a33eddb59ffce828e29f11499304`.

## Pins And Limits

| Existing configuration | SHA-256 |
|---|---|
| `configs/research/semgrep-python-candidate-v1.json` | `ce4b8517a4042bb247ac641250f5d9428e8a5f985db69d36f2d9fef28f09e23c` |
| `configs/tools/agent-audit-pilot.toml` | `0cbc071b465e1f8a965df3419042f52aee6e6f592668a5fd4c1426f12590313a` |
| `configs/profiles/source-pilot.toml` | `d8ee765569cde2f87107ace4ddd04f64c3cccd253af462f04bff4f934df1aa6c` |
| `configs/dependency/tools.json` | `176c2099bc13a2c7d120c27ca014e91808bbcaba58bfa017d79b7e84cd6b8f96` |
| `configs/dependency/osv.toml` | `0ce7ce124bbe33592a7d166230971e220f7f59177b6b0e295983fe7506757871` |
| `configs/dependency/syft.yaml` | `aff991297d3b515fe9fb0a8467cc26c3a419421aa0c5bdc61e74422ca84c18d7` |
| Platform `uv.lock`, not target lockfile | `b072464773b77a68d6f03345f6f913568773903671821eb6b61d4ea312fcfb6c` |
| Frozen PyPI database | `6f7b248e44eeadbf0d669c2e2842adc19bc1929f1b9da8ae2e69991dab3cbbdd` |

The existing Agent Audit configuration supplies image/native flags and validation resources;
its historical `python-source-pilot-v1` label must not become a false description of MCP results.
The new execution contract must name Python and MCP stages explicitly without changing old pins.
The two-agent-stage split is engineering organization of the approved inputs, not a new detector.

## Explicit Omissions And Interpretation

- `Dockerfile`: present, unsupported by the admitted KICS profile, not run.
- `kiro-power/skills/setup/SKILL.md`: present, inventory only; no skill-poisoning detection claim.
- `kiro-power/plugin.json`, CI YAML, other metadata: inventoried, no dedicated detector treatment.
- FastMCP dynamically registers wrapped functions through `self.tool(...)`. Generic Python
  analysis is eligible; full tool-registration/dataflow recognition is not established.
- Source includes memory search/store behavior and configurable descriptions. This is not
  memory-poisoning, prompt-injection or runtime/effective-permission coverage.
- MCP launch arguments name an unversioned package and reference environment placeholders.
  Inspect those declarations unchanged; do not resolve them or equate the configured future
  installed package with this pinned Git source. No secret value is inferred from a placeholder.
- Public vulnerability expectations are unknown. Report claims, contextual review, unsupported
  properties and failures separately; do not compute public precision/recall without an oracle.
- The fixed database supports a controlled historical comparison, not a latest-advisory verdict.

Next: implement/test a separate execution and evidence-replay contract, then run the three
repetitions and build the report. Preserve the earlier LangGraph pilot and all historical receipts.
See [implementation boundary](../../../docs/qdrant-pilot.md).
