# Private Agent Image Recovery

This helper transfers the two **unchanged** admitted images from
`configs/tools/agent-audit.toml`. It does not build a new scanner, change a treatment, admit a
repository, install target dependencies, run an agent or download images. Keep its output in
ignored `workspace/` or `releases/`, not Git. Third-party distribution clearance remains open.

## Requirements and Identity

- Start Docker Desktop in Linux-container mode. The current images execute on `linux/amd64`.
- The frozen IDs identify OCI indexes with runtime and attestation manifests. Use a compatible
  containerd-backed image store; a legacy store may not preserve these identities. Do not
  substitute config digests, retag a rebuilt image or edit the admitted pins to make import pass.
- The receiving checkout needs the existing locked Python environment. Image recovery does
  not supply host Python, uv, project dependencies, other scanners, the OSV database or evidence.
- Obtain `manifest.json`'s SHA-256 through a trusted project record separately from the incoming
  files. A digest delivered only beside an untrusted archive is not authentication.
- Allow roughly 1 GiB of free staging space for the current export, import copy and logs,
  plus Docker's image storage and the Python environment. This is an estimate, not a quota.

Docker documents [save](https://docs.docker.com/reference/cli/docker/image/save/),
[load](https://docs.docker.com/reference/cli/docker/image/load/) and the
[containerd image store](https://docs.docker.com/engine/storage/containerd/).
The exact OCI-index shape above was observed in the project's retained image export.

## Workflow

Run from the development checkout. Every output directory must be new.

```powershell
uv sync --frozen --all-groups
uv run python tools/transfer_agent_images.py export --output workspace/agent-image-export
```

The final printed line is the manifest digest. Record it separately. Copy the resulting
`images.tar` and `manifest.json` together to a private destination; retain export logs locally.
On the receiving checkout, replace `TRUSTED_MANIFEST_SHA256` with the trusted recorded value:

```powershell
uv run python tools/transfer_agent_images.py verify --bundle workspace/agent-image-export --manifest-sha256 TRUSTED_MANIFEST_SHA256
uv run python tools/transfer_agent_images.py import --bundle workspace/agent-image-export --manifest-sha256 TRUSTED_MANIFEST_SHA256 --output workspace/agent-image-import
uv run python tools/verify_agent_development.py --output workspace/agent-image-rehearsal
```

`verify` does not need Docker. Import does not scan anything; the final command separately
runs the existing 13-case authored matrix and two repeats, under the existing isolation limits.
Its success means the finite integration works, not that a public repository is admitted or safe.

## Guards and Receipts

```text
frozen checkout pins -> inspect two local images -> save by exact IDs
  -> inspect archive metadata and OCI identity chain -> hash archive -> transfer manifest
trusted manifest digest + matching checkout -> checksum/identity validation (no Docker)
  -> new private staged copy -> verify copy -> docker load -> inspect exact IDs
  -> separate controlled matrix -> retained run bundles and validation
```

The helper rejects changed manifests/archives, different treatment pins, unsafe archive paths,
links, duplicate members, unexpected tags/images/platforms and broken OCI identity chains.
It reads outer archive metadata without extracting layers on the host. Import loads only after
these checks and preserves the original manifest bytes. Docker commands have bounded logs,
a ten-minute timeout and a 4 GiB export limit. Failed attempts retain status and logs; retry in
a new directory. A timed-out load may have imported some layers: inspect Docker before retrying.

No pull, build, tag, image deletion, container launch or credential mount occurs in this helper.
It uses the same minimal local environment policy as existing execution. It does not select
remote Docker contexts; the supported setup is the local Docker engine.

Treat the bundle and destination as private trusted storage while verifying/loading. Checksums
detect changes, not a privileged local attacker rewriting both the archive and its trusted record.
Do not use this as a general-purpose importer for arbitrary third-party Docker archives.

## Boundaries

An export/import rehearsal on the same daemon is **not** recovery onto an empty daemon or proof
of another machine's compatibility. A fresh source checkout with a new locked environment is a
separate check; report exactly which was performed. Do not delete working images just to simulate
disaster recovery. Independent-host validation and a complete distributable installation kit remain
open, as do dependency licensing review and source-build reproducibility. Existing preparation
recipes include dependency resolution; rerunning them is not automatically the historical treatment.

The runner hashes all trusted worker-source files. Adding this helper module changes that code
identity. Repeats within this checkout should agree; do not remove identity fields to force equality
with an older source revision. Compare native observations separately when explaining the change.
