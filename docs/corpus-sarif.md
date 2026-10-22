# Corpus SARIF Export

`tools/corpus_sarif.py` is an additive, offline exporter for the retained Python-core
corpus. It consumes the same validated review/queue/report/source bindings as the
review companion. It does not scan, refresh tools, alter findings, approve reviews
or replace historical exporters.

## Mapping And Boundaries

Each repository receives `results.sarif` and `accounting.json`. An index, README,
byte-identical review-proposal export and checksum manifest form one bounded package.
Existing 16 MiB entry and 128 MiB package limits apply without truncation or increases.

Each observed execution cell becomes one SARIF run. Repository revision, producer,
repetition, policy view and custom batch remain distinct. Three observations of one
condition are not three independent vulnerabilities. Rules with the same ID in
different producers do not share a run or implicitly merge.

| Input | SARIF projection | Explicit limitation |
|---|---|---|
| Custom condition | Catalog title, ID, source lines, source/native hashes and original record reference | Native priority is uncalibrated; full record and catalog remain in source evidence |
| Semgrep finding | Reconciled message, anchor, native JSON/SARIF references and policy metadata | Severity, tool version and complete rule metadata are not available in this derivative; no guesses |
| Agent Audit finding | Retained title, rule, source lines, original priority/confidence and separate tier/suppression fields | Descriptions, snippets, remediation and unknown fields remain external; empty runs lack version metadata |
| Inventory / limitations | Separate counts, file states and source bindings | Never emitted as vulnerability results |
| Unobserved cell | Accounting entry and log-level `unobservedCells` property, with null counts | No fabricated SARIF run or successful invocation |
| Draft review | Exact original first-repeat observation linked to `inputs/reviews.json` | No propagation to repetitions, policy counterparts or nearby findings; no acceptance |

All results use `kind: review` and `level: none`. Native severity stays in evidence
properties, not a normalized risk score. No CVSS/security-severity score, runtime
flow, verified fix, suppression request or unique-vulnerability identity is invented.
The corpus fingerprint identifies an observation in a particular execution cell,
not cross-tool equivalence. Native suppression metadata is preserved even when it
indicates an existing suppression; the exporter does not decide that policy anew.

Standard regions contain only lines, with native coordinates retained separately.
The run explicitly declares `unicodeCodePoints`, but emits no column numbers and
makes no UTF-8-byte to character conversion. Source URIs are escaped paths beneath
the exact GitHub revision. Nothing is fetched when exporting.

The derivative does not contain full process records. Accordingly, no SARIF
`invocations` are inferred from an observed-row flag. Native analysis state and
file observations remain in properties and accounting. Full native evidence remains
necessary for replay; this helper reconstructs report derivatives and review bindings.

## Standards Checks

The exporter verifies the existing vendored SARIF schema bytes:
`ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25`.
It validates offline, with no external schema retrieval. It also checks mapping
invariants and prose constraints that JSON Schema alone does not enforce.

The [OASIS SARIF 2.1.0 specification with Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
was checked on 22 October 2026. Relevant sections are 3.27.9-10 (kind/level),
3.14.27 (column units), 3.20.14 (execution status), and 3.35 (suppression).
In particular, a review result cannot have a non-none level. Historical exporters
that combine review with warning/error are not changed under frozen evidence;
do not extend this increment's standards-check claim to those earlier exports.

The pinned schema disallows explicit `results: null`, although the prose discusses
null results. This implementation does not patch the schema or manufacture an
empty scan: unobserved cells remain external to SARIF runs, explicitly retained
in accounting and a log-level property. Generic SARIF viewers may ignore those
properties. The complete package, not a findings-only viewer, is the authoritative
presentation of coverage and omissions.

## Commands

From the development checkout, using retained local evidence:

```powershell
uv run --frozen --offline --no-sync python tools/corpus_sarif.py write `
  --review outputs/corpus_context_review_2026-10-22 `
  --queue outputs/corpus_review_queue_2026-10-22 `
  --reports outputs/corpus_core_collection_2026-10-22 `
  --sources workspace/corpus-admission-2026-10-22 `
  --protocol docs/corpus-collection-protocol.md `
  --output outputs/corpus_sarif_2026-10-22
```

Use `verify` with the same inputs for full regeneration/comparison. The output must
be fresh and disjoint from all evidence inputs. Altered or resealed exports are
rejected when they differ from the source-derived mapping. Every selected draft
review must link exactly once; mismatches fail rather than being silently skipped.

## Verification And Limits

Authored tests cover mapping counts, repeat separation, inventory-only and partial
states, unknown/unsupported outcomes, original native policy, forged approvals,
source changes, identity collisions, escaping, schema/prose checks, loss accounting,
non-overwrite and resealed-output tampering. Real-corpus generation is a separate
offline rehearsal, not a new scanner experiment or outcome validation.

Schema/mapping success is not GitHub Code Scanning or IDE interoperability testing.
No upload is authorized. Outputs remain internal/unredacted; licensing, distribution,
independent review and the final experimental seal are separate decisions. Additional
dependency, MCP-configuration and IaC stages are not covered by this Python-core export.
