# Agent Artifact Contracts and Development Cases

## Implemented Boundary

This increment adds typed records, JSON Schemas, two finite property definitions and thirteen
authored fixture cases. It adds no scanner command, general-purpose detector, repository
discovery, target execution, model call or UI. Existing static/dependency contracts are unchanged.
No additional dependencies were installed. The next adapter increment will consume these records.

The student approved these initial conditions and case categories on 2 October 2026:

- A Python tool passes its parameter directly to `eval`.
- An MCP filesystem-server configuration declares the exact path argument `/`.

Approval covers the finite development scope, not independent adjudication of every fixture,
formal academic approval or final benchmark labels. A corrected case removes only its named
condition; it is not proof that the whole program is safe.

## Records and Relationships

```text
existing TargetSnapshot + InventoryEntry (original file path/hash/length)
  -> AgentArtifact (kind, identified format, parse state, reason)
  -> AgentAssessment (run/execution + producer + property + support/state/count)
       -> existing EvidenceReference (retained blob and optional native locator)

existing Finding + native_extension (future adapter mapping; unchanged here)
  -> existing reporting/export services (future integration)
```

| Contract | Unit and purpose |
|---|---|
| `agent-artifact-v1` | One source-file occurrence in a target snapshot; embeds the existing inventory identity |
| `agent-property-v1` | One named, bounded repository-visible condition with scope and limitations |
| `agent-assessment-v1` | One artifact/property/producer assessment tied to a run and, for observations, an execution |

An artifact can be recognized without being parsed, and parsed without being analyzed. Artifact
kinds include future inventory categories such as skills/memory; their presence in an enum is
not implemented recognition or detection support. `format_id` identifies the intended format,
not a universal MCP schema. `mcp-servers-json` refers to the finite client-configuration shape
in our fixtures, not the MCP wire protocol or every client's configuration format.

Assessment rules enforced by the Pydantic model:

- `complete` requires parsed input, supported analysis, a finding count, execution identity and
  retained evidence. It means evidence-accounting completion, not safety or detector correctness.
- `not-run`, `skipped`, `unsupported` and `unknown` require a null finding count, never a clean zero.
- `partial` and `failed` may retain evidenced counts without becoming successful analysis.
- Any non-null count or native exit code requires an execution identifier. Counts reject negative
  values, booleans, numeric strings and fractional numbers.
- Partial, failed, skipped, unsupported and unknown states require explicit limitations.
- Native exit codes remain observations, not automatic platform-status decisions.

Schemas are in `schemas/agent-v1/`; regenerate with
`uv run python tools/generate_agent_schemas.py`. Use **model validation as well as JSON Schema**:
the exported schemas enforce field shapes, while cross-field consistency is enforced in Python.
These DTOs do not verify blob existence, hashes against files or producer honesty; that remains
the evidence validator's job. Validate serialized records at trust boundaries. Python-level
frozen models do not make nested collections or referenced inventory objects immutable.

## Property Registry and Native Mapping Contract

`configs/agent-artifacts/properties.json` identifies the two conditions. Candidate rule IDs
are observed/prior-art references, not detector implementations or an exact scoring oracle.
In particular, a rule ID alone does not prove that a finding matches our narrow property.

| Native item | Mapping required in the subsequent adapter |
|---|---|
| Rule ID/title/description | Retain in existing `Finding.rule` and message fields; do not collapse overlapping reports into distinct confirmed vulnerabilities |
| Native severity | Preserve its label; use an explicit versioned severity mapping |
| Confidence/tier/actionability/risk score | Retain as native assertions; do not reinterpret as measured probabilities or platform scores |
| CWE/OWASP values | Map only observed values with native attribution; null remains unknown, not filled from a rule-pack guess |
| Native finding and suppression fields | Retain in `native_extension` and immutable native bytes; suppressions must remain visible in counts and exports |
| Artifact path/position | Map to the exact input view and original snapshot; reject escapes, identify synthetic/fallback locations, never fabricate source precision |
| Evidence | Link native result ordinal/JSON pointer and blob hash to the existing finding model |
| Aggregate `scanned_files` | Preserve as a producer assertion, not proof of per-file parsing or coverage |

The preflight MCP `AGENT-029` finding is about the root path. It is **not a package-pinning
finding**. Native output supplied no CWE even though the builtin rule pack contains one; the
adapter must not silently enrich it as if observed. The eval case's `AGENT-001` CWE/remediation
mismatch must also remain explicit. These mapping requirements are documented, not yet an
implemented native-output parser or common-report/SARIF integration.

## Controlled Cases

See [the fixture guide](../test_cases/development/agent-artifacts/README.md) and
`test_cases/development/agent-artifacts/cases.json`.

Each input is stored as a UTF-8 string plus its intended relative path. Deliberately malformed
Python and executable-looking examples are data, not Python modules discovered by tooling.
The unit tests parse only these authored strings with `ast`/`json`; they never import the
fixture, call a tool, invoke `eval`, install LangChain, launch `npx` or execute an MCP server.

Tests assert fixture integrity and the explicitly authored conditions independently of native
scanner results. They do not estimate precision/recall. Exact hashes for treatment runs will
be generated when the subsequent harness materializes a fresh, manifested input view. Do not
reuse these development cases in held-out evaluation.

## Still Required Before Adapter Acceptance

The scanner adapter still needs bounded syntax/shape validation, duplicate-key rejection,
parent-directory policy controls, inline/rule-level suppression accounting, safe derived views,
partial/missing-file accounting, strict native parsing, and common-report/SARIF compatibility.
Tests for those behaviors must accompany their implementation; this increment does not claim
that they already exist. Then run controlled container repeats before admitting source/config
analysis on a pinned public repository. The earlier dependency-only pilot is not such admission.

## Engineering Verification

The 2 October increment passed formatting, lint and mypy checks and all 172 tests on Windows
and in the retained pinned Ubuntu verification image. This includes 57 new tests and the
existing 115-test suite. Linux ran offline with read-only project source and 2 GiB memory;
it was not an Agent Audit scan. No new dependency or image download was required.

Source/output hashes, Windows and Linux JUnit records, and bounded container metadata are
retained locally under `workspace/phase3-contracts-2026-10-02/`. They remain outside Git.
The source checkpoint for this uncommitted increment starts at merged PR #4 (`49052e0`);
this record does not imply a new GitHub CI run or independent review.
