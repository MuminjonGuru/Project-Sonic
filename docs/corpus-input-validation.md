# Corpus Input Validation

This additive gate follows [byte preflight](corpus-preflight.md). It does not change the
two fixed pilot execution contracts or authorize detector collection. The confirmed scope,
three repetitions and pre-scan review sample are in the
[collection protocol](corpus-collection-protocol.md).

## Binding and Execution

`intake.corpus_validation` binds one registered candidate to its replayed intake specification,
full Git-backed inventory, exact preview, selected Python hashes, deterministic input requests,
trusted worker source and protocol/tool hashes. All source path roles remain in the preview.
Baselines are never partitioned: validation partitions only bound the syntax worker and may
later be reused by explicitly file-local custom analyzers.

`intake.corpus_validation_execution` freezes those bytes in a new ignored attempt, inspects the
existing pinned validator image and runs only `agentsec_evidence.agents.worker`. Limits are
90 seconds, one CPU, 512 MiB, 64 PIDs, 64 MiB temporary storage, 64 files/1 MiB per request and
256 KiB per file. Network denied, non-root, read-only input and implementation mounts; no target
imports, installation, execution, scanners or rule changes. Cleanup is checked after each worker.

Retain commands, stdout/stderr, process measurements, requests, source views, frozen implementation,
assessment and a checksum seal. Failure preserves a failed attempt; no overwrite, automatic retry
or successful partial resume. Missing Docker has no host-parsing fallback. The worker image and
Python 3.13 parser are unchanged; unsupported syntax is not a proven defect in the target project.

```powershell
.venv/Scripts/python.exe -m agentsec_evidence.intake.corpus_validation_execution run `
  --project . `
  --candidate-root workspace/corpus-admission-2026-10-22/R03 `
  --output workspace/corpus-input-validation-2026-10-22/R03

.venv/Scripts/python.exe -m agentsec_evidence.intake.corpus_validation_execution verify `
  --project . --output workspace/corpus-input-validation-2026-10-22/R03
```

Create the output parent first; each candidate attempt must be new. The candidate directory must
match its registry ID and exact source revision. The helper is an explicit corpus gate, not the
ordinary CLI's unrestricted directory/URL scanning command.

## Interpretation

| State | Meaning |
|---|---|
| input-eligible | Input/policy gates passed; resources and execution protocol still need admission |
| input-eligible-with-incomplete-files | Custom file-local workers must preserve incomplete file accounting; not complete coverage |
| unsupported-size | Whole baseline selection exceeds its unchanged limits; no baseline findings count |
| input-refused | Whole baseline cannot proceed with the validated selection; do not drop malformed files |
| policy-refused | Unsupported local configuration, inline suppression or native exclusion blocks the treatment |
| no-input | No selected Python files; not a clean security result |

Agent Audit gates inspect the full parent inventory for policy files, including case variants,
and every selected Python input for `noaudit` and known default excluded directories. Semgrep
retains its own two-view policy assessment, not Agent Audit's policy. Every selected file stays
visible; per-file oversize is explicitly unvalidated, never silently removed from the denominator.

Replay verifies the external Git/preflight parent, full selection, exact request/response binding,
frozen source membership, container arguments/isolation, cleanup, process limits and recomputed
assessment. Changed bytes or a resealed inconsistent projection are refused. Hashes establish
consistency, not independent attestation. Replay starts no containers. Portable reports may later
consume this evidence, but native replay currently requires the original external candidate parent.

All counts of security scanner invocations remain zero in this contract. Syntax validation is
not a scanner finding, license clearance, framework detection coverage or runtime safety claim.
Optional MCP/dependency/IaC inputs remain separately selected and validated; YAML filenames or
the existence of an MCP project do not automatically establish a supported configuration.
