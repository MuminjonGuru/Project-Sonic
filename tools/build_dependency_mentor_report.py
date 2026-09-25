"""Build a selected, screen-friendly meeting view from retained engineering evidence.

Authoring-only dependencies: ReportLab. These are not application runtime dependencies.
"""

# ruff: noqa: E501

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
W, H = landscape(A4)
MARGIN = 42
WIDTH = W - MARGIN * 2
INK = colors.HexColor("#202A30")
TEAL = colors.HexColor("#006C70")
GRAY = colors.HexColor("#58656A")
PALE = colors.HexColor("#EDF5F4")
AMBER = colors.HexColor("#815A0D")
SOURCES: dict[str, str] = {}


def read(path: Path):
    data = path.read_bytes()
    SOURCES[path.relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
    return json.loads(data)


def tests(path: Path) -> int:
    data = path.read_bytes()
    SOURCES[path.relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
    suites = ET.fromstring(data).findall("testsuite")
    if not suites or any(int(s.get("failures", "0")) + int(s.get("errors", "0")) for s in suites):
        raise ValueError("Quality evidence is incomplete or failed")
    return sum(int(s.get("tests", "0")) for s in suites)


class Report:
    def __init__(self, path: Path):
        self.c = canvas.Canvas(str(path), pagesize=(W, H), invariant=1)
        self.c.setTitle("Project Sonic - Dependency Evidence and Common Reporting")
        self.c.setAuthor("MuminjonGuru")
        self.c.setSubject("Technical mentor discussion; formative engineering evidence")
        self.page = 0

    def text(self, text, x, top, width, size=12.3, color=INK, bold=False, leading=None):
        style = ParagraphStyle(
            "body",
            fontName="Helvetica-Bold" if bold else "Helvetica",
            fontSize=size,
            leading=leading or size * 1.35,
            textColor=color,
            spaceAfter=0,
        )
        paragraph = Paragraph(text, style)
        _, height = paragraph.wrap(width, H)
        if top + height > H - 40:
            raise ValueError(f"Page {self.page} overflow: {text[:70]}")
        paragraph.drawOn(self.c, x, H - top - height)
        return top + height

    def begin(self, title, subtitle):
        if self.page:
            self.c.showPage()
        self.page += 1
        self.c.setFillColor(TEAL)
        self.c.rect(0, H - 7, W, 7, fill=1, stroke=0)
        self.text("PROJECT SONIC  /  TECHNICAL MENTOR DISCUSSION", MARGIN, 22, WIDTH, 9, TEAL, True)
        end = self.text(title, MARGIN, 48, WIDTH, 25, bold=True)
        self.text(subtitle, MARGIN, end + 8, WIDTH, 11.3, GRAY)
        self.c.setStrokeColor(colors.HexColor("#D5DFE1"))
        self.c.line(MARGIN, 32, W - MARGIN, 32)
        self.c.setFont("Helvetica", 8.5)
        self.c.setFillColor(GRAY)
        self.c.drawString(
            MARGIN, 19, "18 September 2026 | Formative evidence | Not an academic submission"
        )
        self.c.drawRightString(W - MARGIN, 19, f"{self.page:02d} / 09")
        return 126

    def section(self, title, body, top, x=MARGIN, width=WIDTH):
        top = self.text(title, x, top, width, 14, TEAL, True)
        return self.text(body, x, top + 6, width) + 17

    def table(self, rows, widths, top, x=MARGIN, size=11.1):
        style = ParagraphStyle("cell", fontName="Helvetica", fontSize=size, leading=size * 1.3)
        head = ParagraphStyle(
            "head", parent=style, fontName="Helvetica-Bold", textColor=colors.white
        )
        content = [
            [Paragraph(escape(str(v)), head if i == 0 else style) for v in row]
            for i, row in enumerate(rows)
        ]
        table = Table(content, colWidths=widths, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), TEAL),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LINEBELOW", (0, -1), (-1, -1), 0.5, colors.HexColor("#CCD9DA")),
                ]
            )
        )
        _, height = table.wrap(sum(widths), H)
        if top + height > H - 43:
            raise ValueError(f"Table overflow on page {self.page}")
        table.drawOn(self.c, x, H - top - height)
        return top + height + 16

    def code(self, lines, top, x=MARGIN, width=WIDTH, size=10.5):
        lines = lines.splitlines()
        height = len(lines) * size * 1.42 + 20
        if top + height > H - 43:
            raise ValueError(f"Code overflow on page {self.page}")
        self.c.setFillColor(PALE)
        self.c.rect(x, H - top - height, width, height, stroke=0, fill=1)
        self.c.setFillColor(INK)
        self.c.setFont("Courier", size)
        for i, line in enumerate(lines):
            if self.c.stringWidth(line, "Courier", size) > width - 24:
                raise ValueError(f"Code line too wide: {line}")
            self.c.drawString(x + 12, H - top - 16 - i * size * 1.42, line)
        return top + height + 16

    def finish(self):
        if self.page != 9:
            raise ValueError("Unexpected page count")
        self.c.save()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "outputs") or output.exists():
        raise ValueError("Use a new PDF under development outputs")
    output.parent.mkdir(parents=True, exist_ok=True)
    common_root = ROOT / "workspace/common-reporting-final-2026-09-18"
    common = read(common_root / "combined/report.json")
    sarif = read(common_root / "combined/results.sarif")
    verification = read(common_root / "summary.json")
    pilot_runs = read(ROOT / "workspace/dependency-final-public-pilot-2026-09-18/results.json")
    pilot_summary = read(ROOT / "workspace/dependency-final-public-pilot-2026-09-18/summary.json")
    read(ROOT / "workspace/dependency-oracle-audit-2026-09-18/results.json")
    oracle_summary = read(ROOT / "workspace/dependency-oracle-audit-2026-09-18/summary.json")
    admission = read(ROOT / "test_cases/pilot/langgraph-cicd/admission.json")
    tools = read(ROOT / "configs/dependency/tools.json")
    win = tests(ROOT / "workspace/common-reporting-quality-2026-09-18/windows-junit.xml")
    linux = tests(ROOT / "workspace/common-reporting-quality-2026-09-18/ubuntu-junit.xml")
    pilot = next(s for s in common["sources"] if s["label"].startswith("github:"))
    fixture = next(s for s in common["sources"] if s["label"] == "fixture:dependency-basic")
    fixture_run = next(
        r
        for r in sarif["runs"]
        if r["properties"].get("agentsecEvidence/sourceRunId") == fixture["run_id"]
    )
    sample = fixture_run["results"][0]
    if not all([verification["passed"], pilot_summary["passed"], oracle_summary["passed"]]):
        raise ValueError("Cannot present failed verification as completed")
    n = pilot["summary"]["eligible_unique_packages"]
    report = Report(output)

    y = report.begin(
        "Dependency evidence, now in common reporting",
        "Engineering progress, real outputs and the next discussion points",
    )
    y = report.section(
        "The project",
        "<b>Design and Evaluation of an Operational Security Evidence Orchestration Platform for AI-Agent Systems.</b><br/>Reuse established scanners; build the evidence, comparison and reporting layer. This is not a replacement SAST engine.",
        y,
    )
    y = report.table(
        [
            ["Milestone", "What is established", "Boundary"],
            [
                "Existing foundation",
                "Semgrep + KICS evidence paths and shared orchestration",
                "Authored static fixtures; no detection improvement claim",
            ],
            [
                "Dependency pilot",
                f"Two offline paths; {n} eligible identities; three semantic repeats",
                "One pinned public example, not a representative benchmark",
            ],
            [
                "New integration",
                "Common JSON + package SARIF; 19 preserved source bundles",
                "Offline reporting, not another scan or a clean security verdict",
            ],
        ],
        [145, 310, WIDTH - 455],
        y,
    )
    report.section(
        "Takeaway",
        "We can now explain what each tool observed, where an exchange lost information, and when analysis was incomplete. The next research step still needs its own bounded scope and expected outcomes.",
        y,
    )

    y = report.begin(
        "One repository, two controlled paths",
        "A manageable agent example selected for reproducibility, not for its number of findings",
    )
    y = report.section(
        "Selected public pilot",
        '<link href="https://github.com/langchain-samples/cicd-pipeline-example">langchain-samples/cicd-pipeline-example</link><br/>Python/LangGraph text-to-SQL CI example; root uv.lock, tests, prompts/configuration and IaC. MIT notice retained. Intake: 47 files / 2,481,730 bytes. Commit: <font face="Courier" size="10">'
        + admission["revision"]
        + "</font>",
        y,
    )
    y = report.code(
        "PATH A   pinned uv.lock ----------------------> OSV direct\nPATH B   same uv.lock -> Syft -> CycloneDX 1.6 -> OSV SBOM\nBOTH     native bytes -> package evidence -> comparisons -> JSON / SARIF",
        y,
        size=11,
    )
    y = report.section(
        "Fixed treatment",
        f"Syft {tools['syft']['version']} (native schema {tools['syft']['native_schema']}); OSV-Scanner {tools['osv']['version']}; frozen PyPI database. Same explicit OSV configuration; strict offline, all-package output, no exclusions, call analysis or remote resolution. SBOMs stay outside the target.",
        y,
    )
    report.section(
        "What was actually scanned",
        f"Root lockfile only: all markers/groups, {n} eligible PyPI name/version identities plus local text2sql-agent@0.1.0. No dependency installation, build, target tests, agent execution or production access. This is not one installed runtime; pilot material is excluded from held-out evaluation.",
        y,
    )

    y = report.begin(
        "Controlled cases made the result testable",
        "Student-reviewed finite expectations; neither Syft nor direct OSV was used as ground truth",
    )
    y = (
        report.text(
            "Four PyPI identities: Requests 2.31.0 and 2.33.0, transitive urllib3 2.7.0, and development packaging 25.0; editable root separate. An authored, non-installable fixture fragment.",
            MARGIN,
            y,
            WIDTH,
        )
        + 14
    )
    y = report.table(
        [
            ["Controlled treatment", "Attempts", "Observed evidence state / assertion"],
            [
                "Basic fixture, repeated",
                "3",
                "Complete; 4/4 eligible identities; 3/3 expected advisory groups per OSV path",
            ],
            [
                "Unaffected / empty / unresolved",
                "3",
                "Complete / partial / partial; absence and unknowns distinguished",
            ],
            ["Malformed / unsupported", "2", "Failed / failed; not converted into clean results"],
            [
                "Remove component / remove purl / change version",
                "3",
                "Complete / partial / complete; localized handoff differences detected",
            ],
        ],
        [242, 70, WIDTH - 312],
        y,
        size=10.7,
    )
    y = report.table(
        [
            ["Requests 2.31.0: expected alias group", "Associated GHSA", "Frozen fixed version"],
            ["CVE-2024-35195", "GHSA-9wx4-h78v-vm56", "2.32.0"],
            ["CVE-2024-47081", "GHSA-9hjg-9r4m-mvj7", "2.32.4"],
            ["CVE-2026-25645", "GHSA-gc5v-m9x4-r6x2", "2.33.0"],
        ],
        [285, 255, WIDTH - 540],
        y,
        size=10.2,
    )
    report.text(
        "All 11 controlled attempts passed their assertions. Changing the copied SBOM version to 2.32.5 left one expected group. Finite precision/recall was 3/3 per path, not a general accuracy estimate; 'complete' means evidence completed, not no vulnerability.",
        MARGIN,
        y,
        WIDTH,
        11.1,
    )

    y = report.begin(
        "Public pilot: retention, loss and zero matches",
        "All figures below describe the pinned lockfile and frozen database, not the live repository today",
    )
    rows = [["Evidence stage", "Eligible identities", "Advisory groups", "Native relationships"]]
    rows.extend(
        [
            s["stage"],
            f"{s['eligible_reported_packages']} / {n}",
            "Not a matcher"
            if s["reported_package_advisory_matches"] is None
            else s["reported_package_advisory_matches"],
            s["relationships"],
        ]
        for s in pilot["summary"]["stages"]
    )
    y = report.table(rows, [184, 164, 174, WIDTH - 522], y)
    losses = next(
        c
        for c in pilot["summary"]["comparisons"]
        if c["left"] == "syft" and c["right"] == "cyclonedx"
    )
    y = report.section(
        "The useful discrepancy",
        f"All {n} name/version projections survived. However, Syft-to-CycloneDX lost registry-source qualifiers for {len(losses['source_qualifier_losses'])} identities; direct OSV also omitted those qualifiers relative to the lockfile. Therefore, 100% projection retention is <b>not</b> full qualified-identity preservation.",
        y,
    )
    report.section(
        "What zero means",
        "Neither OSV path reported a match against this frozen database. That is not proof of safety, runtime non-exploitability or per-package matching completion. Public precision/recall is N/A without an exhaustive oracle. Relationship counts have different meanings; their fidelity was not scored.",
        y,
    )

    y = report.begin(
        "Common reporting preserves the distinctions",
        "New offline outputs; no original evidence files were changed",
    )
    y = report.code(
        "inspect / summarize / validate / export sarif  <dependency-run-id>\nreport build  <source-bundles...>  --output <new-directory>\nreport validate  <report-directory>",
        y,
        size=11.1,
    )
    y = report.table(
        [
            ["Output", "Meaning"],
            [
                "report.json",
                "common-report-v1: separate static/dependency source views, states, scope and counts",
            ],
            [
                "results.sarif",
                "One run per static source; separate direct and SBOM OSV runs per dependency source",
            ],
            [
                "report-manifest.json",
                "Output hashes/lengths and source-manifest references; reporter source hashes in JSON",
            ],
        ],
        [180, WIDTH - 180],
        y,
    )
    y = report.section(
        "No false uniformity",
        "Package findings have logical package locations and native evidence pointers, not invented file lines or severity. Missing counts stay null. Failed and unsupported evidence never becomes a clean zero. Paired OSV matches are not summed as independent vulnerabilities.",
        y,
    )
    report.section(
        "Mixed demonstration",
        "Four separately labeled sources produce six SARIF runs: the controlled dependency fixture, public dependency pilot, Semgrep fixture and KICS fixture. The static fixture findings are <b>not</b> findings in the public repository. SARIF schema validation passed; external upload compatibility remains untested.",
        y,
    )

    y = report.begin(
        "Actual output: an advisory match and a zero",
        "Selected fields from generated output; omitted fields remain in the preserved machine-readable reports",
    )
    col = (WIDTH - 26) / 2
    report.text("Controlled fixture: OSV direct", MARGIN, y, col, 14, TEAL, True)
    report.text("Public pilot: OSV direct summary", MARGIN + col + 26, y, col, 14, TEAL, True)
    left = {
        "ruleId": sample["ruleId"],
        "kind": sample["kind"],
        "level": sample["level"],
        "locations": sample["locations"],
    }
    # Flatten only the displayed location to keep the excerpt readable; label this projection.
    left_display = {
        "ruleId": left["ruleId"],
        "kind": left["kind"],
        "level": left["level"],
        "logicalName": left["locations"][0]["logicalLocations"][0]["name"],
        "nativePointer": sample["properties"]["agentsecEvidence/jsonPointer"],
        "nativeArtifact": sample["properties"]["agentsecEvidence/nativeArtifact"],
    }
    right_stage = next(s for s in pilot["summary"]["stages"] if s["stage"] == "osv-direct")
    right_display = {
        k: right_stage[k]
        for k in [
            "stage",
            "state",
            "eligible_reported_packages",
            "reported_package_advisory_matches",
            "per_package_matching_completion",
        ]
    }
    end1 = report.code(json.dumps(left_display, indent=2), y + 30, width=col, size=9.3)
    end2 = report.code(
        json.dumps(right_display, indent=2), y + 30, x=MARGIN + col + 26, width=col, size=9.3
    )
    y = max(end1, end2)
    y = report.section(
        "How to read these records",
        "Left: presentation projection with shortened field names; <b>level: none</b> means severity is not mapped, not that the package is safe. OSV exit 1 is a successful finding-bearing scan. Right: exact summary field names; zero matches and unobservable per-package completion remain separate facts.",
        y,
    )
    y = (
        report.text(
            "Native aliases retained for the left record: "
            + ", ".join(sample["properties"]["agentsecEvidence/aliases"]),
            MARGIN,
            y,
            WIDTH,
            11.2,
        )
        + 14
    )
    report.text(
        "Native JSON SHA-256: <font face='Courier' size='9.6'>"
        + sample["properties"]["agentsecEvidence/sourceBlobSha256"]
        + "</font><br/>A JSON pointer plus this hash links the displayed claim back to exact source evidence. No synthetic test advisory is shown here.",
        MARGIN,
        y,
        WIDTH,
        11.2,
    )

    y = report.begin(
        "Verification, runtime and problems resolved",
        "Engineering reproducibility evidence, not a speed or detection-superiority claim",
    )
    y = (
        report.text(
            f"<b>{win} Windows tests + {linux} Ubuntu tests passed.</b> Nineteen retained bundles passed reporting validation; source bytes unchanged; repeated combined SARIF identical. Reporting invoked zero scanners. Pre-change Git bundle restore and fsck passed.",
            MARGIN,
            y,
            WIDTH,
        )
        + 17
    )
    rows = [
        ["Public repeat", "Direct OSV", "Initial SBOM path", "SBOM consumer only", "Whole pair"]
    ]
    for i, run in enumerate(pilot_runs, 1):
        rows.append(
            [str(i)]
            + [
                f"{run[k] / 1e9:.3f} s"
                for k in [
                    "direct_path_wall_ns",
                    "sbom_initial_path_wall_ns",
                    "sbom_consumer_only_wall_ns",
                    "paired_end_to_end_ns",
                ]
            ]
        )
    y = report.table(rows, [130, 137, 166, 177, WIDTH - 610], y)
    y = (
        report.text(
            "Initial SBOM cost includes Syft generation. Three sequential repeats, no warmups, fixed order and uncontrolled host caches: feasibility timing only. Preparation/database downloads are outside measured scans.",
            MARGIN,
            y,
            WIDTH,
            11.3,
        )
        + 17
    )
    y = report.section(
        "Two issues resolved without hiding the evidence",
        "OSV's documented cache layout did not match this pinned build: corrected the mount to <font face='Courier' size='11'>/database/osv-scalibr/PyPI/all.zip</font>; failed attempts were retained. Syft reordered optional-extra metadata: introduced explicit dependency-semantic-v2 canonicalization, keeping original bytes/hashes and separate reanalysis.",
        y,
    )
    report.text(
        "The three final public runs now share one semantic hash. This comparison preserves meaningful content and excludes volatile timing/metadata; it does not require byte-identical native outputs.",
        MARGIN,
        y,
        WIDTH,
        11.3,
    )

    y = report.begin(
        "What this establishes, and what comes next",
        "Discussion prompts after the short update; no new agent-specific implementation started",
    )
    y = report.section(
        "Established",
        "A reproducible dependency-evidence pipeline, explicit exchange-loss accounting, finite oracle/mutation checks and common reporting across file and package evidence. No paid tools, GPU or model API calls were required for this milestone.",
        y,
    )
    y = report.section(
        "Still outside this result",
        "One repository and one ecosystem do not establish agent-security coverage. Prompt injection, skill/tool misuse, memory and runtime behavior were not tested. Broader corpus, held-out evaluation, UI, writing and public-release/IP clearance remain open. Approximate October 25 is a planning target, not a verified institutional deadline.",
        y,
    )
    y = report.section(
        "1. Accept this foundation?",
        "We have repeatable dependency results, can expose information lost between tools, and now report them together with earlier static evidence. Is this sufficient engineering evidence to close this bounded dependency stage, while keeping broader evaluation separate?",
        y,
    )
    y = report.section(
        "2. Bound the next agent-specific test?",
        "The pilot inspected dependencies, not agent behavior. I propose agreeing one repository-visible agent artifact, one observable risk condition and positive/negative expected cases before implementation. Which would best support the thesis question?",
        y,
    )
    report.section(
        "3. Protect the remaining delivery time?",
        "We still need agent-specific evidence, a justified wider sample, a usable demo and the dissertation. What should be the minimum acceptable evaluation depth, and what should be deferred to protect completion?",
        y,
    )

    y = report.begin(
        "Technical reference and reproducibility",
        "Backup page for questions; full raw evidence remains in the private development workspace",
    )
    y = (
        report.text(
            "<b>Isolation:</b> non-root Docker, denied network, read-only source/database/root, no socket or credentials; 2 CPUs, 2 GiB, 256 PIDs, 120 seconds per scanner stage. stdout/stderr capped at 2 MiB each; generated files polled at 64 MiB aggregate, not a hard filesystem quota.",
            MARGIN,
            y,
            WIDTH,
            11.1,
        )
        + 13
    )
    rows = [["Frozen identity", "Value"]]
    for label, value in [
        ("Repository commit", admission["revision"]),
        ("uv.lock SHA-256", admission["lockfile_sha256"]),
        ("PyPI database SHA-256", admission["database_sha256"]),
        ("Public semantic-v2 SHA-256", pilot_summary["semantic_sha256"][0]),
        ("Syft image SHA-256", tools["syft"]["image"].split("sha256:")[1]),
        ("OSV image SHA-256", tools["osv"]["image"].split("sha256:")[1]),
    ]:
        rows.append([label, value])
    y = report.table(rows, [184, WIDTH - 184], y, size=9.4)
    y = (
        report.text(
            "<b>Local audit trail:</b> dependency-oracle-audit, dependency-final-public-pilot and common-reporting-final workspaces dated 2026-09-18; quality JUnit files; source hashes in this PDF's artifact-manifest.json. Reproduction commands: docs/dependency-pilot.md and docs/common-reporting.md. Original bundles and the frozen database must be retained separately.",
            MARGIN,
            y,
            WIDTH,
            10.4,
        )
        + 12
    )
    report.text(
        '<b>Primary references:</b> <link href="https://github.com/anchore/syft/releases/tag/v1.52.0">Syft 1.52.0</link>; <link href="https://github.com/google/osv-scanner/releases/tag/v2.6.0">OSV-Scanner 2.6.0</link>; <link href="https://google.github.io/osv-scanner/usage/offline-mode/">OSV offline mode</link>; <link href="https://github.com/CycloneDX/specification/tree/1.6/schema">CycloneDX 1.6 schema</link>; <link href="https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html">OASIS SARIF 2.1.0</link>.<br/>Version-specific behavior was checked against executed builds and retained output. This PDF is an AI-assisted engineering synthesis for student review, not external approval or public-release clearance.',
        MARGIN,
        y,
        WIDTH,
        10.2,
    )
    report.finish()
    manifest = {
        "purpose": "screen-shared mentor discussion; not academic submission",
        "source_files_sha256": SOURCES,
        "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "pdf": output.name,
        "pdf_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "pages": report.page,
        "counts": {
            "windows_tests": win,
            "ubuntu_tests": linux,
            "retained_bundles": verification["source_bundles"],
        },
        "limitations": [
            "Selected output excerpts, not full evidence archive",
            "No new scanner execution",
            "No independent attestation or public-release clearance",
        ],
    }
    (output.parent / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"pdf": str(output), "pages": report.page, "sha256": manifest["pdf_sha256"]}))


if __name__ == "__main__":
    main()
