# Chunked Reports and Explicit Report-Only Recovery

## Scope and Decision

On 22 October 2026 the student approved bounded report-only recovery after dbt's
105 native core invocations completed but its 17,501,914-byte JSON derivative
exceeded the existing 16 MiB retained-file limit. This is user-confirmed conversation
approval, not independent review. The original collection remains failed and immutable.
No scanner, rule, input, database, worker limit or target-execution policy changes.

The separately versioned tools are outside the frozen runtime package. V1 report,
collection and evidence contracts remain unchanged. There is no automatic retry.

## Report V2

`tools/corpus_report_v2.py` rebuilds a verified native attempt into a portable,
internal/unredacted report folder:

- `report.html`: repository scope, per-producer/repetition results, coverage and limitations.
- `report.json`: the same summary and a deterministic observation index.
- `observations/NNNN.json`: one complete observation, including its semantic projection.
- `observations/NNNN.html`: escaped native details, linked from the summary.
- `evidence-manifest.json`: every derivative member's byte length and SHA-256.

No observation is dropped, deduplicated or truncated. The index reconstructs the
complete v1 JSON projection exactly. HTML excludes only its redundant semantic
projection, as v1 HTML did; JSON retains it. All three repetitions remain separate.
Generated numeric paths never derive from untrusted source names. Native strings are
escaped, scripts/network resources are prohibited by CSP, and no native/source files
are automatically exported. Sharing still requires review.

The unchanged limits are 16 MiB per member, 128 MiB per package and 4,096 members.
The full proposed package is validated before writing. A single oversized observation
or oversized package is refused, not silently split/dropped or granted a larger budget.
Derivative validation is not native attestation: `verify` additionally rebuilds from
the retained native evidence and compares every projected field and byte.

## Recovery Eligibility

`tools/collect_corpus_core_v2.py prepare` requires a fresh, separate output directory,
the failed parent collection, its candidate ID and explicit report-only approval.
Under the parent's writer lock it verifies:

1. The parent journal has exactly one terminal failure, not an interrupted scanner.
2. Native replay completed, and plan/admission hashes match the frozen treatment.
3. The rejected report has exactly the two expected members and matching hashes.
4. Its only manifest validation errors are the existing per-file size constraint.
5. Its JSON and HTML equal reconstruction from native evidence.

The forensic read allows at most 32 MiB per rejected member, solely to establish
the cause. This does not accept that report under v1 or alter a scanner/report budget.
Other failures, changed bytes, missing output and incomplete execution remain ineligible.

Preparation creates new v2 derivatives for previously completed/reference attempts
and the recovered attempt, with zero scanner invocations. A sealed linked plan binds
the parent's input manifest and journal head, the original failure's evidence, each
attempt/report hash and the new helper/spec bytes. Inherited results retain their
origin: existing formative reference, completed parent, or report-only recovery.

## Continuation

Only the remaining original pending entries may execute, in frozen order and with
unchanged preparations/admissions. Native evidence stays under new append-only attempts.
The original event schema remains suitable, but the linked plan/status contracts are
v2. New events start from the new input-manifest hash. Parent history is reverified;
it is never rewritten to success. All failures/interruption block again without retry.
Writer locks, native replay, membership checks and current implementation pins apply.

```powershell
.venv\Scripts\python.exe -X utf8 tools\collect_corpus_core_v2.py prepare `
  --project . --parent workspace/corpus-collection-2026-10-22-01 `
  --output workspace/corpus-collection-2026-10-22-02 --recover R07 `
  --approve-report-only-recovery
.venv\Scripts\python.exe -X utf8 tools\collect_corpus_core_v2.py status `
  --project . --output workspace/corpus-collection-2026-10-22-02
```

Preparation/status commands do not scan. `run --count N` separately continues at most
N pending repositories. Recovered scans are counted once and reported as reused;
report generation/replay time is not scanner time. Optional stages remain outside core.
Reports are descriptive observations, not confirmed vulnerabilities or measured accuracy.
