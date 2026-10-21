"""Self-contained report styles; no fonts, scripts or external resources."""

STYLES = """
:root { color-scheme: light; --ink:#20262a; --muted:#53606a; --line:#d6dfe1;
  --paper:#fff; --accent:#086d69; --wash:#f2f6f6; --warning:#8a4615; }
* { box-sizing:border-box; letter-spacing:0; }
body { margin:0; background:var(--paper); color:var(--ink);
  font:15px/1.55 system-ui,Segoe UI,Arial,sans-serif; overflow-wrap:anywhere; }
a { color:var(--accent); text-underline-offset:3px; overflow-wrap:anywhere; }
a:focus-visible,summary:focus-visible { outline:3px solid #b66b13; outline-offset:4px; }
.skip { position:absolute; left:12px; top:-80px; background:white; padding:12px; z-index:5; }
.skip:focus { top:8px; }
header { border-top:6px solid var(--accent); background:#202a2d; color:white; padding:28px 5%; }
header p { color:#d7e4e3; max-width:920px; margin:8px 0; }
h1 { font-size:30px; line-height:1.2; margin:8px 0 12px; }
h2 { font-size:23px; line-height:1.3; margin:0 0 14px; }
h3 { font-size:17px; line-height:1.35; margin:22px 0 10px; }
h4 { font-size:15px; margin:8px 0; }
.eyebrow { font-size:13px; font-weight:700; }
.layout { display:grid; grid-template-columns:190px minmax(0,1fr); max-width:1500px; margin:auto; }
nav { padding:26px 18px; border-right:1px solid var(--line); }
nav a { display:block; padding:8px 4px; text-decoration:none; border-bottom:1px solid var(--line); }
main { min-width:0; padding:28px 32px; }
section { padding:0 0 30px; margin-bottom:28px; border-bottom:1px solid var(--line);
  scroll-margin-top:12px; }
.notice { border-left:4px solid #b66b13; padding:10px 14px; background:#fff6e9; margin:16px 0; }
.metadata { display:grid; grid-template-columns:170px minmax(0,1fr); gap:7px 18px; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
.table-wrap { overflow-x:auto; max-width:100%; margin:12px 0; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:var(--wash); text-align:left; color:#35464c; }
th,td { border-bottom:1px solid var(--line); padding:10px 9px; vertical-align:top;
  overflow-wrap:anywhere; }
td { min-width:65px; } tbody tr:nth-child(even) { background:#fafcfc; }
caption { text-align:left; font-weight:600; padding:6px 0; }
.status { font-weight:600; } .muted { color:var(--muted); }
details { border:1px solid var(--line); border-radius:4px; margin:10px 0; }
summary { padding:11px 14px; cursor:pointer; font-weight:600; overflow-wrap:anywhere; }
.detail-body { padding:0 14px 14px; min-width:0; }
pre { font:12px/1.6 Consolas,monospace; white-space:pre-wrap; overflow-wrap:anywhere;
  background:var(--wash); padding:12px; max-height:440px; overflow:auto; }
code { font:12px/1.5 Consolas,monospace; overflow-wrap:anywhere; }
.finding { padding:16px 0; border-bottom:1px solid var(--line); }
.finding p { white-space:pre-wrap; overflow-wrap:anywhere; }
.coverage { display:grid; grid-template-columns:minmax(140px,2fr) minmax(100px,3fr) 65px;
  gap:12px; align-items:center; margin:10px 0; font-size:13px; }
progress { width:100%; height:12px; accent-color:var(--accent); }
footer { color:var(--muted); padding:22px 5%; border-top:1px solid var(--line); font-size:12px; }
@media(max-width:760px) { .layout { display:block; } nav { display:flex; flex-wrap:wrap; gap:8px;
  border-right:0; border-bottom:1px solid var(--line); padding:12px 18px; }
  nav a { padding:6px; } main { padding:22px 18px; } h1 { font-size:26px; }
  .metadata { grid-template-columns:1fr; gap:2px; } dd { margin-bottom:10px; }
  .coverage { grid-template-columns:minmax(90px,2fr) minmax(70px,3fr) 50px; gap:6px; } }
@media print { body { font-size:10pt; } header { background:white; color:#20262a; padding:10px 0; }
  header p { color:#53606a; } nav,.skip { display:none; } .layout { display:block; }
  main { padding:0; } section { break-before:auto; } h2,h3,h4 { break-after:avoid; }
  .table-wrap { overflow:visible; } th { background:#eee; } tr { break-inside:avoid; }
  pre { max-height:none; overflow:visible; font-size:8pt; }
  a { color:inherit; } }
"""
