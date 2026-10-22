# Descriptive Corpus Collection Protocol v0.1

Status: student-confirmed scope and review budget, 22 October 2026. This is an execution
specification, not academic approval, final outcome labels or a replacement research plan.
No wider-corpus detector collection has started when this version is written.

## Frozen Scope

- Keep all twenty revisions in `test_cases/corpus/candidates-2026-10-21.json`.
- R01 and R02 remain previously inspected formative pilots. The other eighteen are a
  purposively selected descriptive corpus, not a representative or held-out test set.
- Select all pinned `.py` files, including examples, tests, CI and documentation source.
  Report those roles separately. Do not call repository file presence deployment evidence.
- Retain the seven custom families, tool-execution 1.1.0 and the other six existing repairs;
  retain the unchanged 68-rule Semgrep candidate in research and policy views and pinned
  Agent Audit. Inventory-only families are not vulnerability detectors.
- Custom analysis is file-local with deterministic bounded partitions. Baselines are
  whole-selection only: no limit increases, splitting, first-64 selection or input removal.
- Three fresh sequential repetitions per eligible stage, approved on 22 October. These
  measure repeatability and timing, not three independent repository samples.
- Keep `.gitignore` disabled in both Semgrep views; apply only the supported Semgrep policy
  and inline suppressions in the policy view. Custom results are research-only.
- Seven size-limited candidates stay in the corpus with null baseline counts and explicit
  unsupported states. The other thirteen remain provisional until input/policy validation.
- Paired comparisons use only the actual common eligible input population. Unmatched custom
  results remain descriptive and are never pooled into a paired superiority calculation.

## Input and Execution Gates

Complete Git evidence and preflight replay precede bounded offline Python syntax validation.
Every file remains accounted for. A syntax refusal is not a repository vulnerability. Custom
workers may preserve incomplete-file records; a baseline cannot omit malformed files merely
to finish. Agent Audit default exclusions, local configuration and `noaudit` markers remain
explicit blockers. Successful input validation is not detector execution authorization.

Use read-only targets, network-denied non-root containers, bounded CPU/memory/process/output
budgets and confirmed cleanup. No target installation, import, execution, agent operation or
model calls. Retain every attempt; failed or interrupted attempts cannot be silently resumed.
Rules, binaries, databases, source inputs and harness bytes must be pinned before each attempt.
Changed implementation requires a new identified attempt, not edited historical evidence.

## Pre-Scan Review Sample

The student approved a maximum of 60 custom condition observations, capped at 12 per active
family, plus up to 20 baseline observations. The following deterministic implementation
specification is frozen before new findings; it is a descriptive audit, not a prevalence sample.

1. Sampling unit: one native condition record bound to candidate ID, revision, stage/family,
   rule ID, source path, source hash, native record identity and location. Keep all raw records.
2. Use the first successfully verified repetition. Repeats are repeatability evidence, not
   additional review candidates. Separately investigate any disagreement across repetitions.
3. Custom sample: active-condition records only, excluding inventory/deferred entries. Within
   each of the five active families, sort by SHA-256 of canonical JSON containing the fixed
   seed `sonic-corpus-review-v1-2026-10-22` and the observation identity. Take the first twelve
   or all if fewer. Break hash ties by canonical identity bytes. Never fill from another family.
4. Baseline sample: the first Semgrep research view and Agent Audit Python only; take up to ten
   records from each producer using the same identity ranking. Do not count the corresponding
   Semgrep policy view again. Suppression effects remain a separate policy comparison.
5. Keep the two old pilots identifiable in the sample and tables. Report the actual distribution
   by repository, producer, family and path role. Empty strata stay empty; no favorable replacement.
6. Review every example used to claim an improvement separately, whether sampled or not. Label
   this purposive addition and exclude it from the fixed-sample denominator. Optional MCP,
   dependency and IaC findings require separately identified review, not pooling into this sample.

For each reviewed record capture the exact scanner claim, source condition, relevant context,
observed mitigation, uncertainty, overlapping reports, reviewer/provenance and evidence hashes.
Use `supported-static-condition`, `claim-not-substantiated-as-worded`, `inventory-only`, or
`unresolved`. A supported static condition is not verified exploitability. Distinguish security
relevance and recommended verification from syntactic agreement. Keep unresolved records visible.
Label reviews student/AI-assisted unless a named independent reviewer actually reviews them.
This sample supports descriptive claim-support counts, not whole-corpus precision/recall,
novel vulnerability counts, calibrated risk scores or independent validation.

## Measurements and Remaining Gates

Report exact selected/validated/analyzed input denominators, tool states, raw condition and
inventory counts separately, policy differences, native/export discrepancies, required human
intervention, stage/end-to-end timings and semantic repeatability. Do not add counts across
families, stages or repetitions as unique vulnerabilities. Unsupported/error counts stay null.

This version freezes selection, repetition and review policy, not complete execution admission.
Before detector collection: replay the validation receipts, bind exact tool/rule/resource
configuration, review license evidence for the intended private analysis, finish runner/report
bindings and document optional stage applicability. Root license discovery is not per-file
redistribution clearance. Raw targets and reports remain ignored/internal pending sharing review.

Optional dependencies require an exact supported lockfile selection and frozen PyPI database;
MCP requires actual supported JSON, not an inferred MCP server configuration; IaC requires
supported Terraform/Kubernetes inputs. YAML filenames alone do not establish Kubernetes.
Dockerfiles, skill files, general prompts/memory and runtime authorization stay unsupported
where no admitted check exists. No new rule or optional stage is smuggled into the fixed core.
