# Scoring Review Guide

This additive helper turns an existing validated scoring bundle into a review-action index.
It does not change measurements, labels, scanner rules, old schemas or evidence. It is not the
results UI. Output contains no automatic finding groups, overall score or accepted decisions.

```powershell
uv run --offline --locked python tools/build_scoring_review.py --bundle outputs/scoring-example --output outputs/review-example
```

The output parent must already exist inside the project's `outputs` directory. The destination
must be new, outside protected evidence. The helper verifies scoring-derivative integrity and
consistent rendering using the existing validator, not native-source replay. It writes:

- `REVIEW.md`: selection, review topics, attempt states and the pending acceptance checklist.
- `DETAILS.md`: all matching rows/repetitions, metric limits, local evidence links and hashes.
- `review-guide-manifest.json`: original derivative hashes, renderer hash and output hashes.

Topic counts are measurement rows, not findings. Rows can belong to several topics. Ratios with
unknown or empty denominators are not turned into measured losses. A full name/version ratio
does not hide added identities or source-qualifier differences. No selected review means unknown
review status, not acceptance. Source findings and report-bound adjudication remain separate.

This is internal navigation, not a sanitized sharing bundle. Raw evidence is not opened or
rendered; links may expose sensitive local data. Data strings escape explicit Markdown/HTML
markup; the helper constructs only local links. A viewer may still auto-link plain URLs or
apply its own extensions, so this is not a viewer sandbox. JSON pointers are printed separately.
Topic selection uses a fixed measurement-name rubric, not an exhaustive risk classification.
Source hashes are recorded claims
from the scoring bundle, not freshly verified native evidence. Moving the guide can break links.

The helper checks original derivative hashes before and after rendering and refuses overwrites.
Regenerate to another sibling directory to compare outputs. Existing `score validate --replay`
retains its stricter current-analysis requirement: adding source files can require a new scoring
derivative for fresh replay. Do not weaken that check or rewrite an old scoring bundle.

## Design References

- [NIST SSDF 1.1, PW.7.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf):
  record and triage analysis issues in the development workflow. Our action index is an
  engineering interpretation, not a NIST-prescribed output or a compliance claim.
- [SARIF 2.1.0 plus Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html):
  execution, provenance, identity and suppression information have distinct meanings. This
  guide preserves those distinctions; it adds no new SARIF fields or consumer-compatibility claim.
- [CycloneDX SBOM guide](https://cyclonedx.org/guides/sbom/lifecycle_phases/): explicit inventory
  completeness and known unknowns support retaining limitations beside component counts.
- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support):
  consumer support and fingerprint behavior require separate verification. Schema validity alone
  is not proof of how a consumer will display, correlate or preserve our results.

Sources consulted 16 October 2026. This bounded review does not change pinned tools/databases,
admit a target, constitute a systematic review or establish analyst productivity improvement.
