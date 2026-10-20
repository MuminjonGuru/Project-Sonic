# Controlled Dependency Input-Boundary Governance

The shared benchmark runner now admits the four existing September input-boundary fixtures
through a separate `benchmark-dependency-boundary-plan-v1` contract. This does not expand the
older paired/mutation plans or admit new repositories, package ecosystems, tools or databases.

| Case | Boundary | Interpretation |
|---|---|---|
| `dev-dependency-empty-v1` | Valid format with no package entries | Preserve OSV no-package exits and missing reports; missing findings are null, not zero |
| `dev-dependency-unresolved-v1` | Package name without an exact version | Preserve unresolved scope and any downstream assertions without treating them as eligible matches |
| `dev-dependency-malformed-v1` | Invalid TOML | Verify the retained input/parser failure; no scanner launch |
| `dev-dependency-unsupported-v1` | Unsupported lockfile format version | Verify the retained input/parser failure; no scanner launch |

These fixtures share the dependency development family and historical engineering expectations.
They are neither independent ground truth nor held-out evaluation cases. Existing source and
expectation bytes, tool/configuration pins, frozen database and current implementation are bound
before execution. Re-pinning edited inputs cannot grant admission.

## Execution and Evidence

Use the unchanged dependency producer: direct OSV, one Syft discovery/export and SBOM OSV when
input parsing succeeds. Targets are never installed or executed. Containers remain pinned,
offline, non-root, read-only and resource-limited. Original native reports remain unchanged.

The boundary verifier replays snapshot identity, native invocations, parsed stages, database
records, comparisons and report status. Only this new contract permits OSV exit 128 without an
output report, for the fixed empty-input case. The output state is `not-produced` with null
counts and the retained exit code. Missing or malformed output under other exits remains an
unverified execution failure. Parsed package appearance is not proof of successful matching.

Malformed/unsupported inputs fail before the producer copies metadata into its run bundle.
Replay uses the preserved prepared snapshot, checks exact admitted bytes and parser error,
and rejects unexpected native artifacts. The producer's `failed` state remains
`execution-failed`, with zero scanner invocations, null package/finding counts and an explicit
input-failure reason. This is verified failure evidence, not a successful security scan.

**Failures still block the session.** A matching expected failure does not authorize continuing
later cells, retries or repairs. Use separate plans for the two parser-failure treatments;
repetitions after the first failure remain `not-attempted`. Status/run return exit 5 for blocked
sessions, preserving the existing CLI policy. Partial completed attempts can be reused only after
full evidence replay; status and reuse launch no scanner.

## Commands

From the development root with the existing environment, images and frozen database prepared:

```powershell
$db = 'workspace/dependency-preflight-2026-09-18/database/osv-scanner/PyPI/all.zip'
uv run python tools/prepare_development_benchmark.py `
  --treatment dependency-boundaries --plan-id dependency-boundaries-01 `
  --case dev-dependency-empty-v1 --case dev-dependency-unresolved-v1 `
  --repetitions 2 --database $db --output workspace/dependency-boundaries-01.json

uv run agentsec-evidence benchmark validate workspace/dependency-boundaries-01.json
uv run agentsec-evidence benchmark dry-run workspace/dependency-boundaries-01.json
uv run agentsec-evidence benchmark run workspace/dependency-boundaries-01.json
uv run agentsec-evidence benchmark status workspace/dependency-boundaries-01.json
```

Prepare separately named plans for malformed and unsupported inputs. Use a fresh plan after
source changes; never rewrite a historical plan. Retained replay requires the original host
paths and database. This is not independent-host reproduction, scoring or a final-study freeze.
Research/pilot governance remains the next MP-04 integration; MP-05 scoring and MP-06 usefulness
review follow. UI and final delivery remain last.
