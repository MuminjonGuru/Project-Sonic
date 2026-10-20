# Bounded Offline Repository Intake

This increment prepares a full pinned repository from cached evidence and re-verifies the
result. It is not a security scan, automatic repository acquisition or scanner admission.
The existing one-repository pilot contracts and historical receipts remain unchanged.

## Input Contract

Supply an externally retained `repository-intake-spec-v1` and a cache containing:

| File | Meaning | Limit |
|---|---|---:|
| `source.zip` | Source archive with one enclosing directory | 16 MiB compressed |
| `commit.bin` | Exact raw Git commit-object payload, not a pretty-printed Git log | 1 MiB |
| `tree-exact.json` | Complete recursive tree response with `truncated: false` | 4 MiB |

The specification pins all three SHA-256 values, full lowercase SHA-1 Git revision and root
tree, expected regular-file count/bytes, source label, asserted license status and evidence
role. Roles are `development`, `formative-pilot` or `demo`; this contract does not admit held-out
evaluation. A label or asserted license status is not source authentication or legal clearance.

The first reusable treatment limits intake to 1,000 regular files, 32 MiB total source content
and 16 MiB per source file. These conservative preparation limits fit the existing bounded
retained-evidence reader while preserving two source copies and metadata. They are not scanner
limits or a claim that larger repositories are unsafe. Oversized input is refused, not truncated.

Raw commit payloads avoid the earlier preparation wrapper's dependence on a supported GitHub
signature-response layout. Signed and unsigned payloads are checked by their Git object identity;
neither author signatures nor repository origin are authenticated. Acquisition remains a separate
step and must not run target hooks, code, package installation, agents or repository tests.

## Commands

```powershell
agentsec-evidence target prepare-git --spec workspace/candidate-spec.json `
  --cache workspace/candidate-cache --output workspace/candidate-prepared --json
agentsec-evidence target verify-git workspace/candidate-prepared `
  --spec workspace/candidate-spec.json --json
```

The output parent must exist and the destination must be new. Cache/output overlap and linked
evidence paths are refused. Keep the original external specification: a manifest stored beside
the files is not an independent trust anchor. Neither command accepts a repository URL to fetch,
runs a scanner or starts Docker. Verification is read-only and cannot repair an old package.

## Processing And Retention

Preparation loads the bounded specification; retains and checks cached bytes; reconstructs Git
commit/tree/blob identities; checks the complete archive membership; materializes the verified
source; creates the existing content-addressed snapshot; and builds the existing filename-based
artifact inventory. The source and snapshot copies are replayed before the receipt is sealed.

All pinned files remain inventoried, including examples, tests, docs, CI and ignore/configuration
files. Symlinks, submodules, Git LFS pointers, path collisions, unsafe paths and unsupported modes
remain refused through the existing verification contract. Missing archive members, including
files omitted by archive attributes, are not silently accepted. Empty trees are not supported.

The package contains `intake-spec.json`, `raw/`, `git-verification.json`, `source/`, `snapshots/`,
`artifact-inventory.json`, `receipt.json` and `evidence-manifest.json`. Preserve it internally:
the complete source can contain sensitive text and is not automatically cleared for distribution.

`verify-git` checks exact manifest membership, bounded plain files, every size/hash, the external
specification, reconstructed Git evidence, both copies of every source file, snapshot provenance,
inventory accounting and derived receipt fields. It rejects extra files and the research reader's
otherwise permitted root runtime directory. Rehashing altered contents alone cannot bypass Git
and external-spec replay. Checks establish recorded consistency, not resistance to an attacker
who can also replace the externally trusted specification, nor immutable storage attestation.

## Output Meaning

- `prepared` means cached input and a full regular-file inventory verified, not safe software.
- `failed` and `unsupported` preserve a receipt and bounded available evidence after the output
  directory is created. Preflight failures such as an invalid spec or existing destination create
  no new attempt. A failure to write/seal storage itself may leave an incomplete attempt; retain it.
- Exit 0 means the preparation/replay operation completed; exit 5 means it did not. Neither is
  a security finding count. Failed/unsupported packages cannot pass `verify-git`.
- Scanner invocations are zero, findings are null, source-content parsing is not performed and
  scanning authorization remains `not-granted`.
- Artifact families are filename candidates, not proven framework support or detection coverage.
  Families without a recognizer remain unknown; category counts can overlap and are not additive.

The user-facing commands compose established primitives instead of relaxing the original fixed
pilot. New scanner treatment/selection, policy handling, syntax validation, repository admission,
and CLI-to-HTML execution remain subsequent work. A Python MCP server does not necessarily include
an MCP client configuration that the configuration analyzer can inspect.
