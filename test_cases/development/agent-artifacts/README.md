# Agent Artifact Development Cases

Thirteen authored data cases for the first Python/MCP integration. These are not downloadable
third-party repositories, an installed environment, an exploit demonstration or held-out data.

The student approved the two named conditions and positive/corrected/near-miss, malformed and
exclusion/suppression categories on 2 October 2026. Exact fixture text is AI-authored and has
not received independent expert adjudication. The `cases.json` provenance statement records this.

| Cases | Independent expected condition |
|---|---|
| `python-positive` | A directly decorated tool passes its parameter to `eval` |
| `python-corrected` | Uses bounded `ast.literal_eval`; no `eval` call for this property |
| `python-near-miss` | Eval-shaped string only, no call |
| `python-malformed` | Not assessable due to invalid syntax |
| `python-inline-suppression` | Same positive condition with `# noaudit`; suppression is not absence |
| Three `python-excluded-*` cases | Same positive condition with each supported config filename excluding it |
| `mcp-positive` | Exact `/` argument for the declared filesystem server |
| `mcp-corrected` | `/workspace/data` instead of root; only this condition removed |
| `mcp-near-miss` | Root mentioned in descriptive text, not granted as a path argument |
| `mcp-malformed` | Not assessable due to invalid JSON |
| `unsupported-text` | Not a supported Python/MCP input |

Package-version pinning is deliberately not this MCP condition. All three valid MCP cases
use the same package declaration; do not interpret absence of the root condition as a clean
dependency or overall security result. Declared paths do not establish effective runtime access.

`expected_condition` is an authored source fact. It is not an expected total native finding
count. One condition can trigger several overlapping rules; extra rule outputs require review.
`expected_parse` describes the input; it does not mean a scanner actually parsed it.

Inputs are embedded as JSON strings to prevent accidental import/execution and allow deliberate
syntax errors without breaking repository quality tools. A future harness must materialize
the recorded paths/bytes in a new development-only directory, preserve original inputs, and
record any trusted policy overlay separately. Do not run or install these examples.

The current checks validate only authored fixture structure and model constraints. Native
suppression behavior, parent-policy precedence and safe scanner integration remain subsequent
adapter tests. Positive/corrected/near-miss outcomes must still be measured against the scanner.
