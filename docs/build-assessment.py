#!/usr/bin/env python3
"""Regenerate ASSESSMENT-2026-07-26.{html,pdf} from the .md — reproducibly.

Before build #10 the three files were rebuilt by hand with no script, which is exactly the
kind of un-reproducible step this project otherwise avoids. This is that missing generator.

Pipeline (matches how the current HTML was produced — pandoc/weasyprint are NOT installed here,
Edge is):
  1. body  = python-markdown(the .md)   extensions: extra (tables/fenced code/attr_list) + toc
  2. html  = <existing head + cover page, preserved verbatim> + body + </body></html>
  3. pdf   = Microsoft Edge --headless --print-to-pdf (the @page CSS in the head drives layout)

The head+cover template is taken from the CURRENT html (everything before the first content
<h1 id=...>), so the hand-tuned print CSS and cover page are preserved across regenerations and
this stays idempotent for the header.

Run:  python docs/build-assessment.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import markdown

DOCS = Path(__file__).resolve().parent
MD = DOCS / "ASSESSMENT-2026-07-26.md"
HTML = DOCS / "ASSESSMENT-2026-07-26.html"
PDF = DOCS / "ASSESSMENT-2026-07-26.pdf"

# Edge is the installed headless-print engine on this host.
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

# The cover page's <h1>HackPit</h1> carries no id; every CONTENT heading gets one from the toc
# extension. So the first `<h1 id=` is exactly the boundary between template and generated body.
BODY_MARKER = "<h1 id="


def build() -> None:
    if not MD.exists():
        sys.exit(f"missing {MD}")
    if not HTML.exists():
        sys.exit(f"missing {HTML} (needed for the head+cover template)")

    old_html = HTML.read_text(encoding="utf-8")
    cut = old_html.find(BODY_MARKER)
    if cut == -1:
        sys.exit(f"could not find {BODY_MARKER!r} in the existing HTML — template boundary lost")
    header = old_html[:cut]  # <head> + full print CSS + cover page, verbatim

    md = markdown.Markdown(extensions=["extra", "toc"])
    body = md.convert(MD.read_text(encoding="utf-8"))

    # THE TOC MUST BE REBUILT, NOT PRESERVED.
    # It sits BEFORE the first `<h1 id=`, so it falls inside `header` — which is
    # copied verbatim. That silently froze it: the shipped ToC still ended at
    # build #9 while the body had grown two builds past it, because nothing ever
    # regenerated the list. The `toc` extension only *inserts* a ToC where a
    # `[TOC]` marker appears in the markdown; with no marker it just assigns
    # heading ids and leaves the rendered list on `md.toc`. So splice it in.
    start = header.find('<div class="toc">')
    if start == -1:
        sys.exit('could not find <div class="toc"> in the template — ToC boundary lost')
    end = header.find("</div>", start)
    if end == -1:
        sys.exit("unterminated toc div in the template")
    header = header[:start] + md.toc.strip() + header[end + len("</div>"):]

    HTML.write_text(header + body + "\n</body>\n</html>\n", encoding="utf-8")
    print(f"  wrote {HTML.name} ({HTML.stat().st_size:,} bytes)")

    if not EDGE.exists():
        print(f"  [WARN] Edge not found at {EDGE} — HTML updated, PDF left unchanged.")
        return

    with tempfile.TemporaryDirectory() as profile:
        subprocess.run(
            [
                str(EDGE),
                "--headless",
                "--disable-gpu",
                f"--user-data-dir={profile}",   # avoid clashing with a running Edge
                "--no-pdf-header-footer",
                f"--print-to-pdf={PDF}",
                HTML.as_uri(),
            ],
            check=True,
            timeout=180,
        )
    print(f"  wrote {PDF.name} ({PDF.stat().st_size:,} bytes)")


if __name__ == "__main__":
    print("== regenerating the assessment (md -> html -> pdf) ==")
    build()
    print("done")
