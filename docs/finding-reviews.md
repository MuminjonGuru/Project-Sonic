# Contextual Finding Reviews

This offline increment records interpretations of retained **public-pilot Agent Audit finding occurrences**. It does not rerun scanners, modify their findings, authenticate reviewers, or calculate accuracy. Other scanner families and the original controlled-case mapping review are not yet supported by this sidecar service.

## Evidence and Interpretation

1. Validate the existing common report's bytes, source references, read-model consistency and SARIF accounting through the existing reporting validator. Original source bundles are not reopened in this operation.
2. Read a supplied annotation batch and bind each subject to the exact report/source/run/execution/record identity and original finding snapshot.
3. Check cited artifact paths and byte hashes against the source inventory.
4. Write a new review directory containing `review.json` and `review-manifest.json`.
5. For a correction, retain the entire earlier annotation sequence and append a new annotation that supersedes the latest annotation hash for that review ID.

Scanner severity, confidence, location, evidence references, normalized assessment, and native extensions remain in `subject.finding_snapshot`. In particular, a native actionability tier and a suppression boolean are separate fields, not interchangeable statements. A contextual conclusion never changes the original `unreviewed` finding assessment. Grouping, remediation summaries, and overall security scores are outside this increment.

An occurrence is identified by `(source_run_id, finding.run_id, finding.execution_id, finding.record_id)`. Repeated executions remain distinct. Eight review anchors across three repetitions represent 24 finding occurrences, not 24 vulnerabilities or independent evaluation cases.

## Contracts

Generated JSON Schemas are in [`schemas/review-v1`](../schemas/review-v1). Pydantic validators enforce additional relational constraints that JSON Schema alone does not express.

| Contract | Purpose |
|---|---|
| `finding-review-batch-v1` | One supplied batch of 1-256 annotations |
| `finding-review-sidecar-v1` | A revision with all prior annotations and newly appended records |
| `finding-review-manifest-v1` | Exact file size/hash, report manifest hash and annotation count |

Each annotation includes:

- A stable review ID and an exact source/finding identity, including a semantic SHA-256 of the full normalized finding snapshot.
- Declared reviewer identity, role, authorship and timezone-aware record timestamp.
- A decision, a contextual conclusion, observed condition, rationale and explicit uncertainty.
- Cited source paths and byte hashes; optional source line ranges and mapping notes.
- The superseded annotation hash for a correction, and optional **measured** review duration. Unmeasured effort stays `null`, not zero.
- `runtime_exploitability: not-tested`. This static workflow cannot establish runtime exploitation.

Reviewer roles are `ai-assistant`, `student`, and `external-reviewer`. Authorship is `ai-drafted`, `ai-assisted`, or `human-authored`; an AI role must use `ai-drafted` and may only propose. These declarations are not signatures or proof of academic approval.

| Decision | Meaning |
|---|---|
| `proposed` | A retained interpretation awaiting a human decision; mandatory first state |
| `accepted` | A declared human retains the previous conclusion, with rationale |
| `changed` | A declared human revises the interpretation; prior text stays available |
| `unresolved` | A declared human records that the assessment remains unresolved |

Supported conclusions are `claim-not-substantiated`, `condition-observed-context-unresolved`, `condition-supported`, and `unresolved`. They are not automatically false-positive/true-positive labels. Acceptance of an unresolved conclusion does not resolve it. A correction may return a previously accepted interpretation to unresolved; a new AI proposal cannot silently replace a human decision.

## CLI

Run from the development checkout with the locked environment. The report path must identify an existing validated derivative. Build that report using the normal source-validating report workflow; reviewing an existing derivative does not itself repeat native-source validation. Paths below are placeholders, not files supplied by the installation.

```powershell
uv run --frozen --offline --no-sync agentsec-evidence review build `
  <report-directory> <annotation-batch.json> --output <new-review-directory>

uv run --frozen --offline --no-sync agentsec-evidence review validate `
  <new-review-directory> --report <report-directory>

uv run --frozen --offline --no-sync agentsec-evidence review build `
  <report-directory> <correction-batch.json> --previous <prior-review-directory> `
  --output <next-review-directory>

uv run --frozen --offline --no-sync agentsec-evidence review validate `
  <next-review-directory> --report <report-directory> --previous <prior-review-directory>
```

To author a batch, copy the exact finding object from the selected public source's `summary.repetitions[].agent_findings[]`; do not reconstruct it from a summary or edit its fields. Use `ReviewSubject` with `semantic_hash(finding.model_dump(mode="json"))`, and validate the batch with `ReviewBatch`. Cite matching `summary.inventory.records[].source` path/hash pairs. The Python models are in [`reviews/models.py`](../src/agentsec_evidence/reviews/models.py); authored round-trip examples are in [`test_public_pilot_reporting.py`](../tests/integration/test_public_pilot_reporting.py). No real reviewer identity should be copied from an authored test.

`review validate` reports the latest annotation for each review ID and separately counts pending proposals and occurrences with a human decision. The latter includes unresolved decisions; it is **not** a count of confirmed security issues or completed adjudications. `vulnerability_total` is always `null`.

Commands return exit 5 on invalid data, unsafe paths, failed report validation or attempted overwrite. Schema generation is local: `uv run --frozen --offline --no-sync python tools/generate_review_schemas.py`.

## Integrity and Limits

- Output must be new and outside finalized evidence/report/review bundles. A previous revision is never overwritten. A failed write may leave an incomplete directory; retain it and use a new path rather than treating it as valid.
- Source reports, previous reviews and input batches use bounded reads and plain paths; symlinks/reparse paths and hard-linked files are refused by the shared file helpers. Sidecars are limited to 8 MiB and 4,096 annotations. Split further work into separately identified records rather than dropping history.
- The review reader caps report JSON at 16 MiB and SARIF at 64 MiB before calling the common-report validator. These are review-interface limits, not new limits on the underlying scanner.
- The original finding snapshot is matched to the validated report, including native metadata. Merely recalculating a modified finding's hash does not make that finding admissible.
- Source context hashes are compared with the inventory records embedded in the report, not rehashed from original repository files. Line ranges and relevance remain reviewer assertions; this service does not prove that a rationale correctly interprets the source. Report generation and separate native-evidence replay have their own validation receipts.
- A revision records its predecessor's byte hash and includes its annotation prefix. Supplying `--previous` verifies that actual predecessor and exact prefix. Without it, the result explicitly says `not-provided`; historical existence is not independently proven. Check each link when auditing a longer chain.
- This is a local append-only **workflow**, not write-once storage or a signed audit service. Filesystem owners can rewrite/reseal files, declare someone else's identity, or create branches. Preserve checkpoint hashes externally to a revision and resolve competing branches explicitly. Do not infer authenticated approval or tamper-proof history from a passing check.
- The report-binding hash is exact: an intentionally rebuilt report with different metadata needs a fresh binding, not silent reassignment of old review records.
- No secrets are redacted here. Review sidecars copy finding text and may contain sensitive source excerpts; keep them internal under the existing release policy. No GitHub upload occurs.

## Current Acceptance Boundary

Importing the older eight-anchor assessment ledger into this format is a provenance-preserving proposal migration, not a new source audit. All actual public-pilot annotations remain proposed until the student records a decision; independent review is not assumed. Neither the migration nor authored human-decision tests supply an evaluation oracle.

The master plan's MP-02 remains open until the required student review and remaining controlled-case mapping review are completed. The broader experiment matrix, benchmark governance, scoring, UI and delivery work remain separate packages.
