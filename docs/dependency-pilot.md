# Dependency Evidence: Reproduction and Boundaries

## Supported Treatment

This engineering treatment is root `uv.lock` format 1, lockfile-wide PyPI inventory, with all
recorded marker branches and dependency groups retained. It neither installs the target nor
resolves an installed environment. Editable/local identities are recorded separately. Private
registries, unresolved versions, ambiguous source identities and unsupported formats remain
explicit limitations; they must not be silently counted as successful analysis.

```text
verified source snapshot / root uv.lock
  +-- OSV direct -----------------------------------> native JSON
  +-- one Syft discovery --+--> native JSON
                          +--> CycloneDX 1.6 --> OSV -> native JSON
  -> normalized package occurrences / relationships / alias-aware matches / states
  -> stage comparisons, semantic digest, timings, integrity manifest
```

The finite fixture oracle is `test_cases/development/dependency-basic/expected.json`.
The student explicitly approved its four PyPI identities, separate editable root and three
Requests 2.31.0 advisory groups against the recorded database. This is not a complete oracle
for the public repository or independent academic validation. The fixture is a non-installable
authored lockfile fragment: it tests parsing and matching, not successful dependency resolution.

## Pinned Inputs

- Syft 1.52.0, native schema 16.1.10; image digest in `configs/dependency/tools.json`.
- OSV-Scanner 2.6.0; image digest in the same file.
- CycloneDX JSON 1.6; local schema files and license in `schemas/vendor/cyclonedx/1.6`.
- PyPI `all.zip` SHA-256:
  `6f7b248e44eeadbf0d669c2e2842adc19bc1929f1b9da8ae2e69991dab3cbbdd`.
- Public pilot: `langchain-samples/cicd-pipeline-example`, commit
  `5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf`; admission and source hashes are recorded in
  `test_cases/pilot/langgraph-cicd/admission.json`.

The frozen database and public target are private workspace inputs, not Git contents. Do not
replace the database with today's download while retaining these expectations. If unavailable,
reproduction stops until the matching archive is restored. A fresh archive is a new treatment.
Initial downloads, tool-image preparation, source verification and database indexing occur
outside the measured pair. Do not update tools, rules, inputs or data between paired runs.

## Commands

Run from the development root after `uv sync --frozen --all-groups`. Docker Desktop must use
Linux containers and both pinned images must already be available. The CLI does not perform
database downloads or refreshes. On this Windows checkout the provisioned interpreter is also
available directly as `.venv\Scripts\python.exe`.

```powershell
$db = '.\workspace\dependency-preflight-2026-09-18\database\osv-scanner\PyPI\all.zip'
$hash = '6f7b248e44eeadbf0d669c2e2842adc19bc1929f1b9da8ae2e69991dab3cbbdd'
uv run agentsec-evidence dependencies run `
  .\test_cases\development\dependency-basic\target `
  --database $db --database-sha256 $hash `
  --label fixture:dependency-basic --revision fixture-v1

uv run agentsec-evidence dependencies validate <bundle-directory>

uv run python tools/verify_dependency_pilot.py `
  --database $db --report-directory workspace/my-new-development-check

uv run python tools/run_dependency_public_pilot.py `
  --source workspace/dependency-pilot-intake-2026-09-18/source `
  --database $db --report-directory workspace/my-new-pilot-check
```

Each helper requires a new output directory. The public helper requires the approved pinned
snapshot and admission record; arbitrary public targets are not automatically eligible.
`intake.public_archive.materialize_pinned_archive` verifies commit/tree identity, every Git
blob, bounded sizes, missing/extra files and unsafe entries before materializing source.
Snapshot SHA-256 verification occurs again before scanning. The target is never executed.

For public-source preparation, retrieve the commit metadata, then its exact recursive tree
using `commit.commit.tree.sha`, and the archive at that commit. A tree query by commit ID may
echo the commit ID in its response; that is not the canonical tree identity and is rejected.
Preserve all three responses and the original license notice. The materialization function
is currently a Python API, not a general-purpose network acquisition command.

## Execution and Failure Contract

Containers run sequentially with no network, read-only root and inputs, no host credentials or
Docker socket, dropped capabilities, a non-root UID, two CPUs, 2 GiB memory, 256 PIDs and a
120-second timeout. Generated reports live outside the repository snapshot. Native report
files have a polled aggregate 64 MiB bound; stdout/stderr each have a 2 MiB bound. Polling is
not a filesystem quota and permits transient overshoot. Docker isolation is not a security
proof against a malicious scanner image; use only the pinned trusted tool builds.

Both OSV paths use `--config`, `--offline`, `--no-resolve`, `--no-call-analysis=all`,
`--all-packages` and explicit `--lockfile` input. No suppressions or package exclusions apply.
The fixture's conflicting adjacent config tests that implicit directory discovery cannot
change the treatment. OSV findings exit 1 is distinct from execution error 127 or unsupported
input 128. Platform exits: 0 complete evidence, 8 partial, 4 failed; validation failure is 5.
`complete` does not mean zero vulnerabilities, correct detection, or lossless representation.

Pinned OSV uses `/database/osv-scalibr/PyPI/all.zip` under
`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/database`. The initial mount following the documented
`osv-scanner` directory failed; those attempts are retained. The corrected file bind is read-only
and no refresh/network fallback is permitted. This version-specific difference was verified
against the actual [pinned matcher source](https://github.com/google/osv-scalibr/blob/3090dbb7aaa2/enricher/vulnmatch/osvlocal/matcher.go),
not resolved by changing the selected scanner version.

## Evidence and Interpretation

Each `workspace/dependency-runs/dep-run-*` contains source/scope/config copies, harness source
hashes, the finite oracle, raw bytes and execution metadata, normalized stage records, the
database entry manifest, relevant frozen advisory records, comparisons, timings and a manifest.
Validation checks file hashes/sizes, completeness of the manifest, models, native evidence
bindings/pointers and the recorded semantic projection. It is not an independent re-execution
of OSV or a signed/WORM attestation; an administrator could rewrite files and manifests.

Package comparison uses a declared PyPI name/version projection. Source qualifiers and lost
identifiers are reported separately. Native observations, pointers, groups and edges remain
available, but full occurrence/relationship preservation is not inferred from package counts.
OSV all-package output proves reported visibility, not successful matching for each package.
No finding means no reported match against this snapshot, not safety or runtime non-exploitability.

Advisory comparisons use package plus transitive alias group from frozen records, retaining
original IDs. The finite fixture expects three advisory groups, not three raw advisory records.
Public pilot precision/recall is N/A: no exhaustive independent vulnerability ground truth exists.
The observed 159/159 projection retention is not proof of equivalent registry-qualified identity.

`dependency-semantic-v2` ignores raw-byte hashes/timing and canonicalizes known unordered Syft
optional-extra collections. It retains their contents, package versions, states and other context.
The first pilot's v1 mismatch was solely an extras-order difference; old evidence is never
rewritten. The public helper's optional `--prior-bundles` creates separate v2 reanalysis records.
Static `run-semantic-v2` and earlier Semgrep/KICS bundles are unchanged.

Three repeats with no warmups check semantic repeatability, not statistical performance.
Containers are fresh; host filesystem caches and OS load are uncontrolled. Initial SBOM-path
time includes Syft generation plus OSV consumption; consumer-only reuse is reported separately.
Host Docker-client peak RSS is not scanner/container memory consumption.

## Remaining Gates

Dependency SARIF export and integration into the common multi-tool result surface remain open;
the existing Semgrep/KICS SARIF contract is unchanged. Additional ecosystems, full relationship
fidelity, broader corpus/ground truth, held-out benchmark freeze, agent-specific checks, UI,
disclosure/redaction, source/database redistribution and university IP clearance require their
own decisions. Pilot material must never enter held-out confirmatory evaluation.

Upstream references: [Syft Python support](https://oss.anchore.com/docs/capabilities/python/),
[Syft release](https://github.com/anchore/syft/releases/tag/v1.52.0),
[OSV release](https://github.com/google/osv-scanner/releases/tag/v2.6.0),
[OSV offline mode](https://google.github.io/osv-scanner/usage/offline-mode/),
[OSV source scan](https://google.github.io/osv-scanner/usage/scan-source),
[CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6/schema).
