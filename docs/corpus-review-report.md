# Corpus Review Companion

The additive `tools/corpus_review_report.py` helper presents the frozen descriptive
sample and its AI-drafted source-context assessments. It is not a scanner, a general
adjudication service, or a replacement for the original repository reports.

## Evidence Contract

Inputs are the existing checksum-bound source-context review bundle, frozen review
queue, twenty v2 corpus report packages, prepared pinned source trees, and collection
protocol. The new sampling module preserves the predeclared extraction and selection
algorithm; it does not choose a new sample or tune rules.

The helper:

1. Bounds reads and checks exact input membership and checksums, refusing links,
   reparse paths and hard-linked evidence files through existing retained-file APIs.
2. Binds the collection status/results, protocol and original report manifests.
3. Reconstructs the v2 report derivatives and first-repeat population, reproduces the
   frozen sample, and matches each entire selected finding snapshot. Rehashing a
   modified finding inside the review cannot substitute for matching the report.
4. Rehashes primary and supplementary source citations against the selected source
   inventory, checking excerpt text, line ranges and exact revision-based links.
5. Preserves native Agent Audit tier/confidence and explicit suppression separately;
   checks the corresponding Semgrep policy-view anchors and file states. Unreported
   files remain unreported, without invented exclusion reasons.
6. Reconstructs positional overlap candidates but does not certify a proposed semantic
   grouping. No finding is merged, removed or suppressed.
7. Produces a new portable companion with an index, one page and JSON per review,
   byte-identical selected review/queue exports, and a checksum manifest.

The review contract is `corpus-source-context-review-v1`; the companion is
`corpus-review-html-v1`. Only AI-proposed, student-review-pending rows are supported
in this increment. Human decisions and independent-review declarations are refused,
not inferred from a continuation request. A future acceptance workflow must preserve
the current proposal and record its actual author and decision separately.

## Presentation

The index distinguishes proposed exact-claim outcomes, contextual relevance, native
policy state and repository input eligibility. No sampled reviews is not no findings;
input eligibility is not completed analysis. The two formative pilots remain labelled.
Unsupported baseline stages remain outside paired comparisons. The Python collection
does not silently acquire dependency, MCP-configuration, IaC or runtime coverage.

Each detail page shows the original claim and record identity, draft assessment,
existing controls, uncertainty, suggested verification, policy fields, overlap
proposals, pinned source links and exact excerpts. Narrow custom syntax agreement
must not be presented as detector precision or evidence of operational importance.

The companion uses the existing report styles, escaped text, generated local filenames
and a restrictive CSP. It has no scripts, remote assets, telemetry or server. GitHub
source navigation occurs only when the reader follows an explicit pinned link; no
remote page is fetched by the builder. The portable folder contains selected evidence,
not every original native bundle. Original repository HTML is not rewritten.

## Commands

Run in the development checkout with the locked environment. Paths below refer to
local retained evidence, which is not distributed in Git.

```powershell
uv run --frozen --offline --no-sync python tools/corpus_review_report.py write `
  --review outputs/corpus_context_review_2026-10-22 `
  --queue outputs/corpus_review_queue_2026-10-22 `
  --reports outputs/corpus_core_collection_2026-10-22 `
  --sources workspace/corpus-admission-2026-10-22 `
  --protocol docs/corpus-collection-protocol.md `
  --output outputs/corpus_review_companion_2026-10-22
```

Replace `write` with `verify` and supply the same inputs to reconstruct and compare
the complete output package. A fresh output directory is mandatory. Do not place it
inside a source evidence tree or overwrite a failed build. Verification still needs
the original local inputs; reading the portable HTML does not.

Every file remains under the existing 16 MiB retained-entry and 128 MiB package
limits. No cap is raised to accommodate reporting. A mismatch fails closed.

## Verification Boundaries

Tests use authored source and observations, not the public evaluation corpus or a
new accuracy oracle. They cover changed source/claims, resealed findings, policy
fields, missing/duplicate records, forged approvals, malformed ranges/paths/links,
HTML injection, output tampering, deterministic projection and non-overwrite behavior.
Real-input rehearsal and browser checks are separate receipts under ignored outputs.

This validates reference integrity and presentation, not the truth of a rationale,
runtime exploitability, source provenance beyond the retained chain, or authentic
reviewer identity. Checksums are not signatures. Native scanner evidence is not
freshly replayed by this helper; report derivatives and cited source bytes are checked.
No scanner, target code, dependency installation or model call is launched.

Reports remain internal and unredacted. Public sharing, code/data licensing, optional
stages, core SARIF aggregation and final delivery freeze are separate gates.
