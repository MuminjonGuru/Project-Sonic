# Custom Rule Repair Evidence In Common Reporting

## Status And Scope

This increment connects the seven repaired Python families to **offline JSON/SARIF common
reporting**, using their sealed development evidence. It does not activate new repository
scans, change a rule, execute a target, create a custom-family HTML view, or grant benchmark
admission. Prior common-report contracts and their schema remain unchanged.

The additive `common-report-v5` contains `custom-repair` sources and may coexist with earlier
source types. Its schema is `schemas/reporting-v5/common-report.schema.json`. Ordinary reports
without these sources continue to use v1-v4. The existing `report build` and `report validate`
commands provide access; no new scanner invocation command is implied.

The student's request to continue authorizes this engineering integration. It is not
mentor approval, independent outcome review or permission to publish private evidence.

## Evidence Path

1. Read the sealed family manifest under explicit byte/file/path limits.
2. Verify exact file/directory membership, every retained hash and source snapshot.
3. Check the relevant worker/shared-code, registry and helper pins against the supported
   implementation. A different implementation is refused, not silently normalized.
4. Validate finite input selection, source bytes, the recorded isolated command, image identity,
   exit status, native catalog and condition IDs. Never execute retained code.
5. Preserve all four treatments separately: `all-repeat-1`, `all-repeat-2`, `valid-only`,
   `corrected-controls`.
6. Keep exact request/native JSON text and parsed models together. Their hashes and parsed
   projections must agree. Sorting a derivative's JSON keys must not rewrite native evidence.
7. Export condition records to SARIF and validate the complete projection against preserved
   native data, rather than checking only counts.

The recorded commands are checked for no network, read-only inputs, fixed mounts, non-root
identity, resource limits and the pinned image. This is validation of retained receipts,
not independent proof that a historical process executed exactly as recorded.

The memory worker's original `memory-development-v1` label is preserved despite its longer
`memory-state` family/registry name. No historical contract is renamed.

## Counting And Interpretation

| Unit | Treatment |
|---|---|
| Active static condition | Preserve each native rule ID, record ID, input hash and range |
| Inventory observation | Keep in report JSON; never create a SARIF vulnerability result |
| Deferred rule | Keep its explicit catalog status and limitations; no detection claim |
| Malformed/unsupported/failed file | Preserve null findings and reason, not zero or clean |
| Completed file/treatment | Bounded processing status, not complete security coverage |
| Repeat | Keep separate; repeated findings are not additional vulnerabilities |
| Overlapping family/rule reports | Preserve separately; issue grouping is not performed |
| Suppression/ignore policy | Research-only; local ignores/comments were not applied |
| Unique vulnerability total | Unknown (`null`), never a sum of these heterogeneous units |

Orchestration and agent-to-agent are inventory-only repairs. Their zero condition results
do not establish secure orchestration, trusted delegation, effective permissions or runtime
protection. Even the active families establish bounded source conditions, not exploitability.

The seven repair datasets differ. A combined report over them is a combined **development
evidence report**, not a same-repository comparison, held-out benchmark or measured accuracy.
The controlled expectations remain authored/AI-assisted, without independent validation.

## Export And Privacy

- JSON contains the full native records and exact native text. Older tool-execution output
  can include source expressions. This report is **internal and unredacted**.
- SARIF includes conditions only, with line-based locations and native UTF-8 byte ranges in
  properties. It does not mislabel Python AST byte columns as SARIF character columns.
- Source snippets/expressions are not exported to SARIF. Inventory and the full catalog remain
  in JSON. Export limitations are explicit.
- All custom conditions use SARIF `warning`; original priority remains available as
  **uncalibrated native priority**, not validated severity.
- No automatic deduplication, suppression application, review decision or calibrated security
  score is introduced.
- Common-report validation checks the derivative and its source references; it does not reopen
  original bundles. Building it validates those original bundles.

Existing HTML and benchmark-scoring routes explicitly refuse custom-repair evidence until
their separate semantics are implemented and tested. Older HTML/report behavior remains intact.

## Commands

From the development repository, with the existing environment:

```powershell
uv run --frozen agentsec-evidence report build `
  outputs/tool_execution_shared_ast_2026-10-20-final `
  outputs/network_data_repair_2026-10-20-final `
  --output outputs/custom-report-example
uv run --frozen agentsec-evidence report validate outputs/custom-report-example

.venv/Scripts/python.exe -X utf8 tools/verify_custom_reporting.py `
  --output outputs/custom_reporting_2026-10-20/rehearsal-01
```

Choose a new destination; existing evidence is never overwritten. The rehearsal's fixed
seven input bundles must already exist. It builds twice without scanning, compares report
semantics excluding only `generated_at`, compares SARIF bytes, validates a same-host relocated
copy and verifies that every retained source-evidence file stayed unchanged. This is not
clean-machine or independent reproduction. Retained scanner durations and newly measured
report-build durations are separately named.

## Verification And Remaining Work

`tests/integration/test_custom_reporting.py` covers all seven families, older dependency
coexistence, the existing CLI, exact byte/parsed binding, altered inputs/commands/catalogs,
missing or invented export results, links, duplicate sources, explicit unsupported routes
and additive schema drift. Test-generated process receipts are synthetic, not scanner evidence.

Local results and final regression receipts are under `outputs/custom_reporting_2026-10-20/`
and `workspace/custom-reporting-2026-10-20/`. These private artifacts are not automatically
Git deliverables. The first development test run exposed request-order reserialization and
a mistaken test CLI option; both were corrected, and the failed attempt remains recorded.

Next: define a versioned common-input execution profile, test cross-family overlap and explicit
suppression handling, connect the custom evidence to useful HTML presentation, and separately
admit any public-repository treatment. Existing pilots and historical rules remain fixed.
Do not claim these repairs have already run against public repositories.
