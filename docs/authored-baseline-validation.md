# Authored Baseline Comparison

## Purpose And Scope

This is an additive, development-only F2 treatment. It compares observations from the
existing seven custom families with pinned Semgrep and Agent Audit observations on the
same authored source bytes. It is not public-repository admission, a held-out evaluation,
a vulnerability count, or a scanner-accuracy ranking.

The student approved the controlled-group treatment on 22 October 2026: retain the
original repair-registry groups, validate syntax in isolation, select parsed cases for
the baselines, retain every excluded case, and refuse Agent Audit groups with policy
blockers. Rules, repair sources, expected rule IDs and historical evidence are unchanged.

## Input And Execution Contract

- `baseline_inputs.py` defines seven original-registry groups, each below the existing
  64-file bound. The union is the 385 sources in `shared-custom-validation.md`.
- Input selection uses the isolated Python parser's observations, not expected detector
  results. Malformed, unsupported and failed parsing remain distinct exclusions with
  null baseline counts. Selection is a new authored-case treatment, not a relaxation of
  the public-repository whole-view guard.
- Every selected case keeps its original `family/case.py` path, exact source bytes and
  SHA-256. No target imports, installation, tests or agent execution occur.
- Semgrep uses the unchanged 68-rule candidate profile (SHA-256
  `ce4b8517a4042bb247ac641250f5d9428e8a5f985db69d36f2d9fef28f09e23c`).
  Research and repository-policy views remain separate; both disable `.gitignore`.
- Agent Audit retains its pinned image and input-policy guard. A `# noaudit` marker
  refuses the entire selected group. It is not removed or ignored to improve comparison
  coverage. Semgrep's policy behavior remains independent of that refusal.
- Native tools see a complete original-registry group of eligible files. Agent Audit
  can use that group's context. This is not evidence that dividing a real repository
  into groups preserves context-sensitive results.
- One scanner runs at a time. Containers are pinned, offline, read-only, non-root,
  capability-dropped and bounded to two CPUs, 2 GiB, 256 PIDs and 120 seconds.
  Native report and process-output limits remain enforced. No Docker socket is mounted.
- The default is two fresh baseline repetitions. Every planned row starts as `not-run`
  with null counts. Policy refusals do not launch tools; process failures stop the attempt.
  There is no automatic retry, overwrite or resume.

## Evidence And Interpretation

`baseline_execution.py` freezes source implementation, registries, selected views,
rule files/license, tool configuration and profile before the measured stages. The
runner verifies frozen membership and bytes, preserves commands, stdout, stderr, native
JSON/SARIF and cleanup captures, and seals the attempt even when it fails.

The existing custom-run bundle is verified before reuse. `custom-reference.json` is a
derived first-repetition projection carrying original manifest/native hashes and source
pins. The original custom native bundle remains separate and unchanged. This reference
does not claim a fresh custom execution or a standalone copy of all original evidence.

Offline verification checks manifest membership/hashes, frozen inputs, syntax-derived
selection, invocation isolation, cleanup, native parsing and row projections. Paired
Semgrep findings are reconciled across both views. Repeatability compares native semantic
content, not timestamps or byte-identical output. Timings are engineering receipts, not
a controlled comparison of scanner performance.

Per-file observations support later source-condition review. They do **not** equate rule
IDs across tools. A report on the same line is not automatically the same security claim.
Agent Audit's aggregate file counter does not establish per-file completion. A native
no-finding observation is not proof of safety; a refusal is not a negative label.

## Commands

Run from the development root after verifying the existing local image/rule preparation:

```powershell
uv run python -m agentsec_evidence.custom_rules.baseline_execution run `
  --output workspace/authored-baselines-YYYY-MM-DD-r2 `
  --custom-run workspace/shared-custom-2026-10-22-b64-r2 `
  --rule-source workspace/phase3-semgrep-broad-assessment-2026-10-05/upstream-full-01/source `
  --repetitions 2

uv run python -m agentsec_evidence.custom_rules.baseline_execution verify `
  --output workspace/authored-baselines-YYYY-MM-DD-r2
```

The output must be a new ignored `workspace` child. Verification does not launch Docker.
The module is a finite engineering runner, not the general repository scan CLI.

## Remaining Gates

Review native messages against source conditions before claiming baseline coverage gaps
or false positives. Establish a condition-to-rule mapping before any precision/recall
claim. Generic repository execution and baseline input limits need their own explicit
contract; custom file-local batching does not settle those issues. F3 reporting,
repository admission and the new public-corpus treatment remain separate work.
