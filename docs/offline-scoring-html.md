# Offline Benchmark HTML

`score html` presents an existing `evidence-scoring-v1` bundle separately from the
repository-oriented `report html` output. It is a derivative, not another experiment,
scanner run, native replay, independent review or overall security score.

## Commands

```powershell
uv run --offline --locked agentsec-evidence score html outputs/scoring-example --output outputs/benchmark-html
uv run --offline --locked agentsec-evidence score validate-html outputs/benchmark-html
```

The output parent must already exist underneath project `outputs`. The destination must
be new and outside finalized evidence. Open `report.html` directly; no server, script,
external font, resource fetch or application dependency is required.

By default the folder contains only `report.html` and `html-manifest.json`. Explicit,
repeatable `--include-export` choices are `scores-json`, `plan-json`, `measurements-csv`
and `attempts-csv`. Selected exports retain their exact original bytes under `evidence/`.
No native report, repository file or arbitrary path is copied or followed automatically.
CSV formula-leading text retains the scoring producer's existing escaping; HTML does
not rewrite the exports. This is not a general spreadsheet-sanitization guarantee.

## Evidence Contract

- Validate the exact seven-file scoring bundle, its manifest, typed plan/report and
  canonical generated tables before rendering. Reject duplicate/non-finite JSON, linked
  files, exceeded budgets, changed inputs and inconsistent session/role membership.
- Retain plan order, session, case ID, evidence role, stage/view/path, repetition, attempt,
  row identity, metric version, unit, counts, eligibility, exclusions, unknowns, limitations
  and evidence references. The renderer does not recalculate experiment outcomes.
- Repetition 0 denotes shared accounting or a summary, not another execution. Development
  and formative-pilot sessions are not held-out cases. Case IDs are not independent source
  families; no new family mapping or independent sample count is inferred.
- The pilot overview selects named coverage, count and handoff metrics from repetition 1
  of each selected formative session. All repetitions and other measurements remain in
  the session sections. This is a labelled navigation summary, not outcome-based selection.
- Review topics reuse the existing `scoring.review_guide` predicates. Their overlapping
  counts are measurement rows requiring interpretation, not issues, severity or deduplication.
- Preserve failed, refused, unsupported and unattempted records, including failures before
  recovery. Unknown, undefined, not-applicable and measured zero remain distinct. Workflow
  completion and hashes do not establish security completeness or vulnerability truth.
- Review summaries retain their recorded role, pending decisions and source bindings.
  Original sidecars are not reopened. AI proposals are not human or independent labels.
- Native references are displayed as escaped text and hashes, not clickable filesystem or
  external URLs. Only owned anchors and selected local exports are links.

## Integrity and Safety

The additive `offline-scoring-html-v1` manifest binds seven input file identities, selected
exports, renderer/helper source hashes and HTML bytes. It records internal/unredacted status
and no native replay. Generator identities are not a complete dependency lock or an attestation.
The manifest does not hash itself. A person able to replace the entire package can also
replace its hashes; this is consistency checking, not authenticity or malicious-author detection.

`score validate-html` works after relocation and checks the exact package file set, plain
files, schema/accounting and hashes. It does not re-render HTML, reopen the original scoring
bundle or establish source correctness. Scoring validation during generation is stronger
than standalone package integrity, but is still not `score validate --replay`.

Inputs use the existing 32 MiB per-file scoring bound, a 1 MiB source manifest bound, a
128 MiB combined bound and strict JSON structure budgets. HTML is bounded to 32 MiB and
its manifest to 1 MiB. Oversized input/output is refused, never silently truncated. Output
is write-once with the manifest last. Inputs are snapshotted/rechecked, not locked against
a hostile concurrent writer; use a trusted immutable workspace as elsewhere in this project.

HTML escaping, visible control characters, allowlisted local links and a hash-bound style-only
Content Security Policy prevent evidence from becoming active content. All mandatory data
is available with native keyboard-operable disclosures and no JavaScript. Dense tables scroll
locally on small screens. Print styles support the current disclosure state, not an automatic
fully expanded archival export or an optimized presentation handout.

## Remaining Gates

This first version is **internal and unredacted**. It can contain sensitive source labels,
paths, observations or raw selected exports. Screen/demo and distribution derivatives require
an explicit sensitive-content policy and review. No automatic masking or public-release
clearance is claimed. Human usefulness acceptance, broader repository intake, final delivery
rehearsal and final research evaluation remain separate work.
