# Corpus Collection Driver v1

The developer helper `tools/collect_corpus_core.py` schedules the already specified Python
core across the frozen candidate registry. It changes no scanner, limit, rule or core plan.
The helper and this specification are themselves hashed in the collection inputs; they live
outside the runtime package so adding the scheduling layer does not replace prior worker pins.

## Freeze and Run

`prepare --project . --preparations <root> --admissions <root> --output <fresh-workspace-root>`
replays all preparations and requires a separately reviewed `Rxx.json` admission for every new
attempt. It copies the exact admissions and freezes the full registry, protocol, helper and
specification. No admission is inferred from a filename, license label or successful parser.

Optional `--existing R01=<attempt> --existing R02=<attempt>` bindings admit only previously
inspected formative pilots whose complete core evidence matches their preparation and admission.
They remain existing references, not newly executed rows, independent samples or silent retries.
Historical rejected attempts remain retained outside this collection and must be reported too.

`run --project . --output <root> --count 1` starts the first pending repository in registry order.
Larger explicit counts allow sequential whole-repository attempts, never concurrent scanners.
Every new repository receives the existing three repetitions and exact full Python selection.
Custom file-local partitions do not permit baseline sharding. Unsupported stages remain null.

The shared writer lock prevents concurrent driver operations on one collection. Before launch,
replay completed attempts and reports, check frozen harness bytes and current implementation,
then exclusively create and flush a start event. A completed finish requires native replay and
verified JSON/HTML reporting. Events form a bounded, append-only SHA-256 chain; hashes establish
consistency, not independent attestation or a tamper-proof external audit log.

## Failures and Evidence

`status --project . --output <root>` replays evidence without launching scanners. Failed attempts,
report failures and interrupted start-only events block further execution. No automatic retry,
failure skipping, intra-repository resume, overwrite or source changes are supported. A subsequent
explicit run can advance only after wholly completed, replay-verified repositories. A failed
attempt's count remains unknown here; its original partial rows and captures remain available.

Admissions and frozen inputs are sealed separately from the growing journal. Each core attempt
retains its own original evidence manifest. Internal per-repository HTML/JSON packages are under
`reports/Rxx`; their hashes are bound by completion events. Nothing is copied into Git. Reports
are unredacted and not cleared for distribution. No new target code, tests, agents or models run.

Optional dependencies, MCP JSON and IaC stay separate from this core treatment. Record candidate
paths and explicit deferment or unsupported status; a YAML filename is not Kubernetes support,
and missing MCP-named files do not prove absence of MCP configuration. Existing optional pilot
results cannot be pooled into fresh core counts. License reviews concern retained private static
analysis only, not legal certification or clearance to redistribute third-party code/snippets.

The frozen descriptive review protocol remains unchanged. Collection completion is not contextual
finding review, confirmed exploitability, representative coverage, precision/recall or final study
completion. Cross-repository tables must distinguish the two existing pilots from new collections,
and paired comparisons from the seven unsupported-baseline projects.
