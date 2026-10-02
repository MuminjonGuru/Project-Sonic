# Common Evidence Reporting

## Agent Extension: 2 October 2026

The [bounded agent runner](agent-static-runner.md) adds an `agent-static` source with explicit
admission, blockers, unknown per-file coverage and native suppression accounting. Reports that
include it use `common-report-v2`; legacy-only reports remain v1. The schema directory retains
its historical name and its common-report schema accepts both discriminated versions. Original
Semgrep/KICS/dependency bundles are unchanged. The sections below describe the earlier v1 scope.

## Purpose and Boundary

This is an offline view over finalized evidence, not another scan. It integrates static
Semgrep/KICS evidence and the bounded PyPI dependency experiment without pretending that a
file finding, a package observation and a package-advisory match are interchangeable.

Original source bundles remain authoritative. The reporter validates them before reading,
creates a new output directory outside finalized bundles and refuses overwrites or duplicate
source IDs. No target execution, Docker call, database update or network request is required.

## Commands

From the development repository, use the appropriate existing workspace and run ID:

```powershell
uv run agentsec-evidence inspect <dep-run-id> --workspace <workspace> --json
uv run agentsec-evidence summarize <dep-run-id> --workspace <workspace> --json
uv run agentsec-evidence validate <dep-run-id> --workspace <workspace> --json
uv run agentsec-evidence export sarif <dep-run-id> --workspace <workspace> --output <new-file>
uv run agentsec-evidence report build <bundle-1> <bundle-2> --output <new-directory>
uv run agentsec-evidence report validate <report-directory>
```

Existing `run_*` commands keep their prior behavior. `dependencies run/validate` remain
available. `normalize` retains its existing static contract; common reporting does not replace
dependency parsing or add a generic re-normalization command.

## Contracts and Counts

| Product | Meaning |
|---|---|
| `report.json` / `common-report-v1` | Discriminated static or dependency source views; identity, hashes, state and limitations |
| `dependency-summary-v1` | Scope, five stage states/counts, comparisons and recorded timings |
| `results.sarif` | One run per static source; two separate OSV runs per dependency source |
| `report-manifest.json` | Output byte hashes and lengths; source-manifest hash references |

Schemas live in `schemas/reporting-v1/`; regenerate with
`uv run python tools/generate_reporting_schemas.py`. Tests check model/schema agreement.

- Static summaries, coverage and failure records retain their original meaning.
- Dependency package counts use the existing, explicit PyPI name/version projection. Lost
  registry qualifiers remain visible in comparison records. This is not full identity fidelity.
- Stage observations, unique package identities, eligible package identities, unique
  package-advisory matches and match occurrences are separate counts.
- A missing stage has null counts, not a clean zero. Counts in failed/partial stages are
  observations, not evidence that analysis completed. No per-package matching-completion
  claim is made where OSV does not expose that state.
- The same advisory group reported through both paths is not two independent vulnerabilities.
  There is deliberately no cross-source vulnerability total or invented overall severity score.
- Different targets may share a report for demonstration; they remain individually labeled.
  Combining fixture and pilot evidence does not make the fixture findings public-repo findings.

## SARIF Mapping

Package results retain canonical alias-group IDs, original advisory IDs/aliases, exact package
name/version, comparison path, native artifact locator, JSON pointer and raw-blob SHA-256.
They use logical package locations, not fabricated source lines. `level: none` means severity
is not mapped; it does not mean safe or informational-only. `kind: fail` represents the reported
advisory match. Candidate package/advisory and occurrence fingerprints remain separate.

OSV exit 1 can mean findings, so completed exit 0/1 invocations are successful. Missing,
unsupported, failed or incomplete stages are unsuccessful with execution notifications.
A completed stage inside an incomplete pipeline carries a warning. Pipeline state and scope
remain in extension properties and the richer JSON summary.

Every run passes the locally pinned OASIS SARIF 2.1.0 schema and existing project checks. This
does not establish that GitHub or another consumer accepts multi-run package-only logs; no
upload was tested. Large-log splitting and consumer-specific mappings remain future work.
The mapping follows [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html),
including logical locations and invocation status rather than treating every nonzero exit as failure.

## Validation and Provenance

`report build` validates source integrity/schema/provenance as supported by each source contract.
`report validate` checks the derivative's hashes, JSON model, SARIF, source linkage and result
accounting. It does not re-open original sources: retain them for independent revalidation.
Hashes are tamper-evident relative to a trusted manifest, not signatures or external attestation.
Reporter module hashes are recorded. Generation timestamps vary; repeated SARIF over identical
sources is byte-identical in the current regression. This is not cross-run native-byte identity.

All products remain internal. Public-release redaction, licensing and source/database
redistribution clearance are separate. The PDF meeting export is a selected, readable view,
not the full evidence archive.

## Engineering Verification

The dated offline helper `tools/verify_common_reporting.py` processes retained development
evidence: 11 controlled dependency attempts, three public-pilot repeats and five static fixture
cases. It hashes every source file before/after, validates 19 derivatives, combines four labeled
sources into six SARIF runs and compares a repeated combined SARIF. It invokes zero scanners.
The output directory must be new and under `workspace/`.

This is formative engineering verification, not 19 repositories or a confirmatory benchmark.
The broader corpus, agent-specific checks and full G2 gate remain open.

## Mentor PDF Rebuild

`tools/build_dependency_mentor_report.py` reads the dated retained reports, admission record and
JUnit files to create a selected nine-page landscape PDF plus an input/output hash manifest.
It requires ReportLab in an authoring environment, not in the application's locked dependency
set. Use a new output filename below `outputs/`; the builder refuses overwrite. It deliberately
fails when required evidence or successful verification is unavailable. The raw workspaces
are not shipped in Git; a clean source checkout alone cannot rebuild this private meeting PDF.

```powershell
<authoring-python> tools/build_dependency_mentor_report.py --output outputs/<new-name>.pdf
```

The separate speaking script lives in the phase planning records, not in PDF notes. Final PDF
QA uses page rendering and text checks; the artifact is not a replacement for the full corpus.
For the recorded layout revision, `tools/verify_dependency_mentor_pdf.py` uses authoring-only
PyMuPDF, pypdf and Pillow, compares all final page rasters to the initially reviewed render,
and identifies changed pages for renewed visual inspection. It is a dated QA helper, not a
generic application command. All nine final pages were verified; no embedded speaking notes.
