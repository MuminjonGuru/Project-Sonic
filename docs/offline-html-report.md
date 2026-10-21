# Offline HTML Reports

The additive `offline-html-report-v1` renderer presents existing validated common reports
(v1-v4) and an optional exactly bound review sidecar. It does not scan, install or execute
targets, rerun tools, refresh databases or follow native-evidence paths. Existing scanner,
common-report and review contracts remain unchanged.

## Commands

Use an existing parent directory under this checkout's `outputs/`. The destination must be new.

```powershell
agentsec-evidence report html <common-report-directory> --output outputs/<new-report>
agentsec-evidence report html <common-report-directory> --output outputs/<another-report> --review <review-directory> --include-export report-json --include-export sarif --include-export review-json
agentsec-evidence report validate-html outputs/<new-report>
```

Open `report.html` directly in a browser. There is no server or application account.
Default output is only `report.html` and `html-manifest.json`. Optional exports are byte-identical
copies of the explicitly selected report JSON, SARIF or review JSON in `evidence/`.
Unknown/duplicate selections and a review export without its sidecar are refused.
No native reports, target files, database or arbitrary path is copied automatically.

The complete folder is relocatable. Validation after relocation checks package accounting and
hashes, not the originals or the meaning of findings. The manifest hashes itself neither
implicitly nor recursively: it records each output's hash and size, input identities and the
three renderer source hashes. It is a consistency record, not a signature or independent attestation.

## Reading the Result

| Section | Interpretation |
|---|---|
| Overview | Retained evidence, source identities and explicit validation scope; not a new scan |
| Source sections | Inventory/selection, coverage, per-stage states, counts with units, timings and dependency handoffs |
| Scanner reports | Each tool, treatment and repetition separately; locations, native assertions and exact SARIF records |
| Contextual review | Only exactly bound review history; AI proposals remain proposals, not human decisions |
| Evidence/exports | Input hashes and selected local exports; pointers to absent native files remain text |

No combined vulnerability score, alert deduplication or inferred runtime exploitability is
introduced. Three repeats are not three independent cases. Native reported paths do not prove
per-rule completion. Package name/version preservation does not prove qualifiers or relationships
survived. No matches do not establish package safety or per-package matching completion.

Public-pilot native findings are enriched only by an unambiguous source/run/execution/fingerprint
binding. Same-line overlap is not a join key. Exact retained source records and review history are
available in disclosure sections. Information absent from a supplied export is not reconstructed.
Cross-case scoring tables are not ingested by this first renderer; they remain separate outputs
under the [scoring contract](offline-scoring.md), not one repository's security verdict.

## Safety and Integrity

- Internal, unredacted output only. Sensitive-content and licensing review precede sharing.
  There is no automatic secret masking or public-release claim in v1.
- HTML escaping, visible Unicode controls, no Markdown interpretation, no arbitrary hyperlinks,
  no JavaScript, external assets or fonts. A restrictive CSP permits only the exact embedded CSS.
- Relative links are renderer-owned anchors and allowlisted exports. Native paths and URLs are
  displayed as text; the renderer does not open them.
- Input file sets are exact. JSON duplicate keys and excessive structures are refused before
  legacy validation; symlinks/reparse paths and hardlinked files are rejected.
- File budgets: report JSON 16 MiB, SARIF 64 MiB, review JSON 8 MiB; each input manifest 1 MiB.
  The strict JSON reader also limits nesting/nodes. Rendered HTML is capped at 32 MiB; excess
  fails rather than silently truncating. These finite limits are not arbitrary-size support.
- Inputs are snapshotted and checked again before publication. This is not an adversarial
  concurrent-writer lock; use a trusted local workspace with immutable evidence.
- New destinations only, outside finalized input/bundle/benchmark/scoring directories.
  Output manifest is written last. Interrupted output is not silently repaired or overwritten.
- Generation validates common-report derivative semantics and optional review binding. Original
  native bundles are not replayed. `validate-html` checks package integrity only, not regeneration.
- Printing preserves the current disclosure state. Collapsed exact JSON is still retained in the
  HTML; a printout is not a substitute for the portable evidence package.

## Verification and Next Boundary

Regression tests cover integrity failures, protected destinations, byte-exact selected exports,
relocation, deterministic generation, HTML injection, absent review, hardlinks, wrong review
binding, changed inputs and controlled policy/syntax refusal states. Existing dependencies suffice;
browser automation is verification tooling, not an application runtime dependency.

The first local examples use the previously admitted public pilot and authored Python/MCP runs.
No new repository or scanner treatment is admitted. Follow-on work is separately bound scoring
presentation, sensitive-content/shareable derivatives, user readability review and reusable
supported intake. Final clean delivery and live-demo rehearsal remain later gates.
