# Network/Data-Transfer Repair v1

Date: 20 October 2026. Second of seven submitted scanner-family repairs.

## Status and Authority

The student supplied the original draft as their own code and approved retaining all
18 IDs while separating defensible static conditions, normal-feature inventory and deferred
checks. This implementation and its syntax expectations are AI-assisted repairs, not
independently reviewed research labels. Original Markdown and extracted payloads are unchanged.

The package has an executable, bounded JSON worker. It is **development-only**, not yet
enabled in the ordinary scan profile, common reports, SARIF, HTML or either public pilot.
This increment does not authorize arbitrary repository scanning or declare real-world accuracy.
No target code, imports, dependencies, network requests or agents are executed.

## Implementation

- [Coverage registry](../src/agentsec_evidence/custom_rules/network_catalog.py):
  immutable-version intent, all original IDs, current status and claim boundaries.
- [Detector](../src/agentsec_evidence/custom_rules/network_data.py):
  bounded Python AST inspection, lexical import resolution and source-bound observation IDs.
- [Shared syntax helpers](../src/agentsec_evidence/custom_rules/python_static.py):
  conservative lexical binding, argument names and explicit UTF-8 byte-column locations.
- [Worker](../src/agentsec_evidence/custom_rules/network_worker.py):
  existing exact input-inventory contract, separate `network-data-development-v1` result.
- [57 authored cases](../test_cases/development/network-data-v1/cases.json) and
  [rule tests](../tests/unit/test_network_data_rules.py) /
  [worker tests](../tests/unit/test_network_worker.py).
- [Offline rehearsal](../tools/verify_network_data_repair.py):
  fixed controls only, four treatments, source snapshots, hashes and retained native output.

The helper extraction from tool execution changes source organization, not its rule contract.
All four tool-execution native outputs were reproduced byte-for-byte against the previous
sealed receipt. The original evidence snapshot remains the authority for that earlier run.

## What Each ID Actually Establishes

There are **10 active static conditions, three inventory-only IDs and five deferred IDs**.
These are not 18 demonstrated vulnerability classes.

| ID suffix | Status | Observable condition and boundary |
|---|---|---|
| 001 | Active | Nonliteral HTTP destination expression; no claim of attacker control or SSRF. |
| 002 | Active | Literal URL user information, credential-shaped query key or credential-like identifier in a URL; not confirmed secret validity. |
| 003 | Active | Interpolation within a URL authority; not necessarily control of the hostname. |
| 004 | Inventory | Explicit response streaming; not a leak or buffering defect. |
| 005 | Active | Credential-like identifier passed directly to print/module logging; name heuristic only. |
| 006 | Deferred | Agent-specific external dispatch needs an admitted framework/API contract. |
| 101 | Active | Nonliteral WebSocket destination; no hijacking claim. |
| 102 | Active | Nonliteral gRPC channel target; no effective-access claim. |
| 103 | Active | Nonliteral S3 bucket/key in an inline boto3 S3 get/put call; no IAM analysis. |
| 104 | Deferred | Chunk tampering needs stream typing and an integrity protocol. |
| 105 | Inventory | Explicit TLS `verify` value; false is visible, not silently treated as safe. No fingerprinting claim. |
| 106 | Deferred | Replay resistance needs operation semantics and server guarantees. |
| 107 | Active | Interpolated DNS name; no covert-exfiltration claim. |
| 108 | Inventory | `SPIFFE_ID` environment read; no proof of mTLS or service-mesh membership. |
| 109 | Active | Nonliteral explicit proxy configuration; not proof of MITM. |
| 110 | Active | Sensitive-name environment read syntactically within URL/query construction; no proven dataflow. |
| 111 | Deferred | Framing integrity needs an identified framing protocol. |
| 112 | Deferred | LLM-selected routing needs routing APIs, policy and source provenance. |

All prefixes are `NET-DATA-`. Low/medium values are provisional **review priorities**, not
validated vulnerability severities, confidence scores or CVSS. IDs 005/107 use low; other active
conditions use medium. Inventory and deferred entries have no finding priority.
No host allowlist reduces priority. A fixed hostname or zero observations is not a safety verdict.

## Repair Rationale

The submitted payload had transport/syntax corruption and mismatched `Finding` construction:
calls supplied `file_line_range` although the dataclass did not define it. Exceptions could
be mislabeled as an AST-parse security finding. The repaired worker distinguishes parse failure,
unsupported input, execution state and static observations instead.

Line-window regexes and adjacent strings are replaced by call-site syntax inspection. Import
aliases are resolved conservatively; shadowed, conditional and ambiguous bindings do not prove
API identity. S3 and streaming classification no longer use always-truthy string branches.
The unsafe URL-extractor path is removed. Normal authentication headers, streaming and default
TLS initialization are not automatically described as vulnerabilities.

The repair removes trusted-host severity exceptions, unproven credential tracing, fabricated
MCP shapes, random hash-based identity, lexicographic priority ordering and advice to obfuscate
exfiltration data or randomize TLS identifiers. MCP remains the existing analyzer's responsibility.
No generic plugin loading, unrestricted tree traversal or target-local imports were retained.

## Supported Syntax, Not Whole-Library Coverage

| API shape | Bounded treatment |
|---|---|
| Requests module methods/request; inline `Session().method` | Destination, inline query dictionary, header presence, explicit verify/stream/proxies. |
| HTTPX module methods/request/stream and Client/AsyncClient constructors | Destination/base URL, query/header options; verify/proxy only where admitted by the signature. |
| Inline HTTPX client methods | Destination/query/header; constructor-only verify/proxy options are reported as unsupported here. |
| aiohttp ClientSession constructor / inline methods | Base URL/header constructor inputs; request URL/query/header/proxy. `ssl` is not inspected. |
| urllib urlopen / ProxyHandler | URL expression / explicit proxy configuration; Requests-specific options are not inferred. |
| websockets connect / websocket-client create_connection | Explicit destination argument only. |
| grpc/grpc.aio channel constructors | Explicit target only; secure/insecure API name is inventory, not credential validation. |
| Inline `boto3.client("s3").get_object/put_object` | Explicit Bucket/Key expressions only. |
| socket getaddrinfo/gethostbyname; dns.resolver.resolve | Supported interpolated name syntax only. |
| print / module-level logging | Direct name heuristic; transformation calls are not secret tracing. |

Assigned client/logger aliases, cross-file flow, effective policy, object types, monkey-patching,
local modules named after libraries and actual runtime reachability remain unknown.
Lambda/comprehension bodies and annotations are excluded; observed unsupported scopes are
reported. Client assignment, expanded arguments and recognized ambiguous calls produce
explicit limitation records. This is not a complete Python interpreter or API argument validator.
Generic opaque methods cannot always be identified as network APIs.

A nonliteral expression can be a constant variable or correctly validated input. An environment
read nested inside a transformation is containment evidence, not proof that its original value
is transmitted. Such limitations must remain beside observations in any future adapter.

### Signature References

Checked on 20 October 2026 against primary API references, without installing target libraries.
These references justify syntax choices, not successful compatibility with all releases.

- [Requests API](https://requests.readthedocs.io/en/latest/api/) and
  [HTTPX API](https://www.python-httpx.org/api/): destination and distinct client/request options.
- [aiohttp client reference](https://docs.aiohttp.org/en/stable/client_reference.html):
  session versus request parameters.
- [websockets client](https://websockets.readthedocs.io/en/stable/reference/asyncio/client.html),
  [websocket-client](https://websocket-client.readthedocs.io/en/latest/core.html),
  [gRPC Python](https://grpc.github.io/grpc/python/grpc.html): explicit endpoint arguments.
- [boto3 S3 put_object](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html):
  Bucket/Key arguments; not access-control semantics.
- [urllib](https://docs.python.org/3.13/library/urllib.request.html),
  [socket](https://docs.python.org/3.13/library/socket.html) and
  [dnspython](https://dnspython.readthedocs.io/en/latest/resolver-class.html):
  proxy and name-resolution inputs.

Online Python 3.13 documentation currently identifies a newer patch release than the actual
3.13.15 validation runtime. The retained image and lock, not the web banner, identify our runtime.

## Input, Evidence and Exit Semantics

The worker validates exact file membership, selection, lengths and SHA-256 values before
inspection and rechecks selected bytes. Bounds: 64 inventory files, 1 MiB aggregate,
256 KiB per input, 50,000 AST nodes and 1,000 observations per file, with an additional
512-entry traversal guard. Links and junctions are refused. Non-Python selections are unsupported.

`complete` means the selected bounded inspections returned, not complete security coverage.
Per-file limitation records and the report-level support boundary remain mandatory even then.
Malformed/unsupported/failed files have **null findings**, not empty findings. Empty selection
is distinct from complete inspection. Exit 0 means no configured threshold was breached;
1 means a review-priority threshold was breached; 2 means partial, empty or refused processing.

Finding output contains location, fixed evidence-kind tokens, canonical API name, source hash
and stable record ID. It does not copy expressions, URL values, credential identifiers or
credential values. Paths and hashes remain identifying information, not anonymous output.
Retained inputs still contain source bytes: this is not blanket clearance to distribute bundles.
Original raw evidence is preserved; no target suppressions are applied in this development mode.

## Rehearsal and Evidence

From this development directory, using the existing pinned validation image:

```powershell
.venv/Scripts/python.exe -X utf8 tools/verify_network_data_repair.py `
  --output outputs/network-data-repair-new-attempt
```

The destination must be new. Source is copied and verified before readonly mounting.
The image is `sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080`.
Runs are sequential, offline, non-root, readonly, capability-dropped and resource-limited.
No Docker socket, home directory or target installation is exposed.
This is an existing local-image rehearsal, not proof of clean-machine image preparation.

Retained final local evidence: `outputs/network_data_repair_2026-10-20-final/`.
The preceding 55-case rehearsal is retained separately, not overwritten. Boundary review then
added controls for literal DNS repetition and unknown unpacked query keys. The first full
regression attempt was intentionally stopped to fix those defects; it is not counted as passing.

| Treatment | Selected | Findings | ID-bearing inventory | State / exit |
|---|---:|---:|---:|---|
| Full controls, repeat 1 | 57 | 30 | 4 | partial / 2 |
| Full controls, repeat 2 | 57 | 30 | 4 | partial / 2 |
| Valid syntax only | 56 | 30 | 4 | complete / 1 |
| Fixed/near-miss controls | 5 | 0 | 0 | complete / 0 |

One malformed case accounts for partial processing. Four valid cases also expose unsupported
or unknown constructs. All expected IDs/states/inventory matched; repeated native JSON was
identical, SHA-256 `8b7372efe2cc84fb3907171120fceb59b660d0c30334b4f8b17806dcaa3edbfc`.
Synthetic secret sentinels were absent from report output. These are authored engineering
assertions, not precision/recall or independent security ground truth.

Tool-execution regression evidence: `outputs/tool_execution_shared_ast_2026-10-20-final/`;
all four output hashes match `outputs/tool_execution_repair_2026-10-20-final/`.
Test/static-check receipts and the final closeout are retained separately under
`workspace/network-repair-2026-10-20/` and the sibling output closeout record.
Neither private execution evidence nor the original drafts are committed by this increment.

## Next Gates

Repair filesystem access next, preserving submitted IDs with honest status boundaries.
Only after controlled family validation should we add a separately versioned common-report
adapter/profile, suppressions policy and scoped public-repository admission. Existing baseline
and pilot outputs must remain separate; this repair does not improve their historical results.
