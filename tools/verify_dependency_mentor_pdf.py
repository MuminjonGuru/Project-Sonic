"""Render and text-check the dated meeting PDF; authoring utilities are separate from app deps."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pymupdf
from PIL import Image, ImageChops
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
pdf = ROOT / (
    "outputs/mentor_meeting_2026-09-18/DEPENDENCY_EVIDENCE_TECHNICAL_MENTOR_REPORT_2026-09-18.pdf"
)
output = ROOT / "workspace/mentor-pdf-qa-final-2026-09-18"
output.mkdir(exist_ok=False)
document = pymupdf.open(pdf)
reader = PdfReader(pdf)
if len(reader.pages) != 9:
    raise ValueError("Expected nine pages")
changed = []
pages = []
text = ""
for i, page in enumerate(document, 1):
    target = output / f"page-{i:02d}.png"
    page.get_pixmap(matrix=pymupdf.Matrix(1.5, 1.5)).save(target)
    previous = ROOT / "workspace/mentor-pdf-qa-2026-09-18" / target.name
    if ImageChops.difference(
        Image.open(previous).convert("RGB"), Image.open(target).convert("RGB")
    ).getbbox():
        changed.append(i)
    content = reader.pages[i - 1].extract_text()
    if len(content) < 500 or "PROJECT SONIC" not in content:
        raise ValueError(f"Missing page content on {i}")
    for annotation in reader.pages[i - 1].get("/Annots", []):
        if annotation.get_object().get("/Subtype") != "/Link":
            raise ValueError("Unexpected PDF annotation; scripts belong in a separate file")
    text += content
    pages.append(
        {
            "page": i,
            "characters": len(content),
            "raster_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        }
    )
expected = [
    "115 Windows tests",
    "115 Ubuntu tests",
    "159 / 159",
    "CVE-2024-35195",
    "not-observable",
]
if changed != [3] or "CVE-TEST" in text or not all(value in text for value in expected):
    raise ValueError("Unexpected final content or layout change")
result = {
    "pages": pages,
    "changed_since_first_visual_review": changed,
    "text_checks": True,
    "pdf_sha256": hashlib.sha256(pdf.read_bytes()).hexdigest(),
    "visual_review": "Final changed page still requires human/assistant image inspection",
}
(output / "qa.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"pages": len(document), "text_checks": True, "changed_pages": changed}))
