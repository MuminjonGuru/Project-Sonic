# Controlled Dependency SBOM-Mutation Governance

This increment governs three existing transformations from the September dependency development
matrix. It reuses the dependency producer and shared benchmark attempt runner. It introduces no
new scanner, public repository, package ecosystem or vulnerability database.

## Admitted Treatments

All cases use the same existing `dependency-basic` target and source-family identity. They are
three interventions on one fixture, not three independent repositories.

| Case ID | Transformation of the copied export | Existing expected diagnostic |
|---|---|---|
| `dev-dependency-remove-component-v1` | Remove Requests 2.31.0 and repair its dependency references | Missing name/version projection at the export handoff |
| `dev-dependency-remove-purl-v1` | Remove that component's package URL only | Missing identifier; partial analysis remains visible |
| `dev-dependency-change-version-v1` | Change to 2.32.5, update its package URL and references, remove obsolete CPE identifiers | Missing old projection, added new version and changed downstream advisory evidence |

These are one admitted transformation per case, not necessarily one changed JSON field. The
version transformation deliberately keeps version-bearing identifiers consistent. The original
Syft JSON and CycloneDX output stay unchanged; the injected discrepancy is not a Syft defect.

The new plan binds the unchanged transformation implementation and historical development helper
as well as the finite oracle, target bytes, configurations, schemas, database and current source.
The helper is an existing engineering expectation source, not independent scientific adjudication.
No outcome is forced to equal these expectations merely to finish an attempt; general scoring
remains MP-05 work.

## Execution and Replay

One cell runs direct OSV, a single Syft discovery/export and then OSV on a preserved changed copy.
Preparation and database download are not repeated during measurement. The existing explicit
OSV configuration, strict offline mode and no-resolution/no-call-analysis settings remain fixed.

The mutation copy has its own change record with source/result hashes and transformation identity.
On status or resume, the verifier reconstructs the mutation from the original export and compares
exact bytes. It also verifies the consumer command used the changed copy, replays normalized data,
comparisons and report fields, and checks source snapshots and database records. A self-consistent
replacement of hashes is insufficient. No scanner is launched by status or completed reuse.

The new plan, preview and progress schemas are in `schemas/benchmark-dependency-mutation-v1/`.
The shared dependency finish/evidence contract is reused unchanged: its fields describe the same
paired stage observations. Existing dependency-v1 plans still admit only basic/corrected cases;
none of their schemas or historical receipts is rewritten to add mutation authority.

Cases run sequentially, with one to three repetitions. Failure or interruption blocks subsequent
cells; no automatic, manual or per-stage retry. The shared writer lock prevents duplicate launch.
Partial analysis can finish an evidence workflow but is neither a clean result nor complete
security analysis. Cell finding totals remain null; direct and SBOM advisory counts stay separate.

## Commands

From the development root with the existing pinned environment, images and database prepared:

```powershell
$db = 'workspace/dependency-preflight-2026-09-18/database/osv-scanner/PyPI/all.zip'
uv run python tools/prepare_development_benchmark.py `
  --treatment dependency-mutations --plan-id dependency-mutations-01 `
  --case dev-dependency-remove-component-v1 `
  --case dev-dependency-remove-purl-v1 `
  --case dev-dependency-change-version-v1 `
  --repetitions 2 --database $db --output workspace/dependency-mutations-01.json

uv run agentsec-evidence benchmark validate workspace/dependency-mutations-01.json
uv run agentsec-evidence benchmark dry-run workspace/dependency-mutations-01.json
uv run agentsec-evidence benchmark run workspace/dependency-mutations-01.json --max-new-cells 1
uv run agentsec-evidence benchmark run workspace/dependency-mutations-01.json
uv run agentsec-evidence benchmark status workspace/dependency-mutations-01.json
```

Use a fresh plan after source changes. Do not re-pin or repair a historical session. Retained
replay requires the frozen database and original host path bindings; this is not a relocated
session or independent-machine reproduction claim. Source files and generated exports are
separate, with no target installation or execution.

## Verification Boundary

Tests cover finite admission, safe unchanged source selection, altered/resealed mutation data,
changed transformation/expectation bytes, consumer input substitution, partial results,
interruption, resume and schemas. Synthetic process tests are distinct from real pinned-container
rehearsals. Keep original, changed and normalized evidence accessible without conflating their roles.

Remaining dependency boundary cases (empty, unresolved, malformed and unsupported inputs) and
research/pilot governance remain separate work. Offline scoring and usefulness review precede
UI and final delivery. No final-study freeze or new repository admission follows from this work.
