# Governed Controlled Research Cases

This MP-04 adapter connects the [controlled producer](controlled-research-execution.md)
to the existing benchmark ledger. It admits only the original fifteen development cases,
not arbitrary repositories, new rules or held-out evaluation data.

## Execution Unit

One cell is one complete case. Registry order is fixed; `defaults` and `inline` retain two
internal repetitions, and the other cases retain one. Each parsed repetition has separate
research and repository-policy passes. Both disable `.gitignore` filtering; repository-policy
applies supported Semgrep exclusions and inline suppression semantics. The original gates
can refuse a case before either pass. These engineering cases are not fifteen independent
repositories or independently reviewed security labels.

The expected full execution is eight observed cases, six policy refusals and one syntax
refusal: twenty scanner invocations and nine isolated syntax-worker invocations. These are
the admitted design's reference observations, **not success assertions in the dispatcher**.
Unexpected detector output must remain measurable, not be discarded as an execution failure.

## Frozen Plan and Evidence

- The plan binds the original registry, profile, execution limits, validator configuration,
  `pyproject.toml`, `uv.lock`, current implementation Python bytes and all 68 rule files plus
  their upstream license. Each case hash includes its full definition and authored expectations.
- Validation is offline: no target parsing, producer invocation, package installation, image
  pull or network access. Expected-output changes cannot be approved by merely re-hashing them.
- The producer retains exact source/policy selection, parent Git evidence, syntax request,
  paired native JSON/SARIF, process/cleanup receipts, dual views and a sealed file manifest.
- Ledger replay verifies those resources against the frozen plan and checks the **exact**
  recorded bind sources, image/flags and generated container identities. Portable common-report
  replay is a different assurance level; it cannot replace original-path ledger verification.
- `execution/environment` retains the two host dependency declarations; `execution/case` is
  the original producer's sealed evidence root. Lock-file retention is not proof of the host
  interpreter or an independently reproduced environment.

## Resume and Failure Semantics

The shared exclusive writer lock and append-only start/finish records apply. A bounded run can
stop between cases; a later run verifies and reuses completed whole cases, then proceeds.
It never resumes inside a case or retries a failed/interrupted case. These plans authorize
zero automatic and zero manual retries. The older opt-in agent pre-launch recovery contract
does not grant this treatment retry permission.

Observed cases remain `partial-analysis`: native counts do not establish complete coverage.
Policy/syntax refusals retain `refused`, zero scanner invocations and **null** finding totals.
Failed/interrupted attempts remain visible and block continuation. Pass counts are separate
by view and internal repetition; there is no sum presented as unique vulnerabilities.
`workflow_complete` means every admitted case has a verified terminal outcome, not that all
analysis completed, expectations matched, or the system is safe.

The `benchmark-research-semantic-v1` projection retains case state, selected-file count,
policy/scope, syntax state and ordered pass rows. Per-pass semantic hashes exclude only
execution identity and native file byte hashes from the reconciled pass evidence. Native
originals, IDs, hashes and process timings remain in the evidence bundle. This is a declared
comparison projection, not byte-identical scanner output or an accuracy score.

## Commands

The original cached rules and pinned local images must already be available. The plan output
parent must exist beneath the ignored workspace and must not be a sealed evidence directory.

```powershell
uv run --offline --locked python tools/prepare_research_benchmark.py `
  --plan-id controlled-research-governed-v1 `
  --rule-source workspace/phase3-semgrep-broad-assessment-2026-10-05/upstream-full-01/source `
  --output workspace/research-plan.json
uv run --offline --locked agentsec-evidence benchmark validate workspace/research-plan.json
uv run --offline --locked agentsec-evidence benchmark dry-run workspace/research-plan.json
uv run --offline --locked agentsec-evidence benchmark run workspace/research-plan.json --max-new-cells 3
uv run --offline --locked agentsec-evidence benchmark run workspace/research-plan.json
uv run --offline --locked agentsec-evidence benchmark status workspace/research-plan.json
```

The same source-bound plan cannot silently run under changed implementation bytes. Earlier
sessions remain historical evidence; their direct evidence replay is distinct from permission
to dispatch more work. New schemas are additive under `schemas/benchmark-research-v1/`.

## Remaining Research Boundaries

No scoring, independently approved expected outcomes, final corpus admission or final-study
freeze is supplied by this adapter. MP-05 offline measurements and MP-06 development-only
usefulness rehearsal follow engineering acceptance. UI and final delivery remain last.
Historical evidence is preserved, not relabeled as a held-out result or hosted CI pass.
