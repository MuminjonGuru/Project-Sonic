# Versioned SARIF Review-Level Correction

`tools/sarif_review_projection.py` provides `sarif-review-level-projection-v1` for
already retained SARIF, without modifying scanners or replay-sensitive historical exporters.
This is an offline delivery projection, not a scan or a finding adjudication.

## Why It Exists

Some historical Agent Audit and common Semgrep projections set `kind: review` while
keeping a non-none level. SARIF permits review results, but its prose requires their
explicit level to be none. Schema validation alone did not catch this combination.
See [OASIS SARIF 2.1.0 plus Errata 01, sections 3.27.9-3.27.10](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html).

Historical emitters and sealed artifacts remain unchanged for exact replay. Their schema
pass receipts must not be presented as complete conformance. Use this versioned correction
for legacy SARIF delivery. The newer corpus export already uses review/none and does not
need to be replaced. Existing HTML remains a historical view, not a link to the new export.

## Contract

Supply the expected SHA-256 from the independently retained parent manifest, rather than
trusting a checksum supplied by an untrusted new package. First verify the parent report
with its own verifier where available. This tool binds only the supplied SARIF bytes; it
does not replay native scanner evidence or authenticate its producer.

The tool reads one plain, non-hard-linked file, rejects symlinks/reparse points, and retains
the existing 16 MiB per-file and strict JSON structural budgets. It never follows artifact
URIs, imports source code, calls scanners or accesses the network. The bundled schema is
hash-pinned and remote schema retrieval is disabled. Invalid JSON/schema, duplicate keys,
metadata collisions, non-fail rank, and other non-review kind/level mismatches are refused.

Only explicit non-none levels on review results are changed. Each previous level and its
source pointer/hash are retained in a new result property, with a log-level projection
record and a separate change ledger. The previous export level is not necessarily the
original scanner severity. Native severity/confidence, suppressions, messages, rules,
locations, fingerprints, run status, ordering and all other JSON values remain intact.
Undoing the declared edits must recover the original JSON exactly. Existing fail kinds are
not promoted, demoted or treated as student-approved vulnerabilities. No grouping occurs.

Already-valid review results keep their absent/none level unchanged. A no-op input still
gets a source-bound package and zero corrections. Re-projecting a corrected export is
refused to prevent misleading provenance chains. A correction can alter presentation or
filtering in consumers; no consumer behavior or upload compatibility is established here.

## Package And Commands

The new folder contains `source.sarif` (original bytes), `results.sarif` (corrected),
`correction.json`, `README.md` and `evidence-manifest.json`. It must be outside the input
evidence folder and must not exist. Partial writes remain visible and cannot be overwritten.
Verification requires the external original hash, validates exact membership/checksums,
and regenerates every member from the original source copy. It does not require the old
host path, but unchanged external source/evidence URIs may still require the original data.

```powershell
.venv/Scripts/python.exe -X utf8 tools/sarif_review_projection.py write `
  --source <verified-legacy-report>/results.sarif `
  --source-sha256 <original-manifest-sha256-for-results.sarif> `
  --output <new-sibling-correction-folder>

.venv/Scripts/python.exe -X utf8 tools/sarif_review_projection.py verify `
  --source-sha256 <same-original-SARIF-sha256> `
  --output <new-sibling-correction-folder>
```

Do not replace original reports, manifests, HTML or native evidence. Do not feed corrected
bytes into an old verifier expecting the original mapping. This contract checks schema,
kind/level and non-fail rank constraints, not every SARIF prose rule. Coordinate semantics,
missing metadata and consumer interpretation retain their original limitations.

Both source and corrected exports are internal/unredacted. This is not an automatically
shareable summary, independent attestation, verified exploitability or a public disclosure.
