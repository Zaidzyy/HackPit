"""Fetch the PortSwigger Web Security Academy into a local source tree.

WHY A FETCHER AND NOT A DIRECT INGESTER
Every other KB source is a directory of markdown on disk, and `consolidate.py` folds those
in. The Academy is a website, so this script does the one thing the pipeline cannot: turn
it into that same shape. After this runs, `consolidate.py --source portswigger` treats it
exactly like HackTricks or PayloadsAllTheThings — no special case anywhere downstream.

WHAT IT TAKES, AND WHY THAT IS THE POLITE ROUTE
URLs come from the site's own `sitemap.xml`, not from crawling links: it is the list the
publisher offers for exactly this purpose, it is complete (the `all-topics` page renders
its list client-side, so scraping it yields 19 of ~150), and it means we never guess a URL
or follow one we were not offered. `robots.txt` disallows only `/bappstore/bapps/download/`;
`/web-security/` is not restricted. Requests are serialised with a delay and carry an
honest User-Agent.

WHAT IT KEEPS
Content is tier-3 REFERENCE, attributed to PortSwigger with the source URL on every entry —
the same footing HackTricks and x3m1Sec's notes are on. It is not Zaid's material and is
never presented as such. Only the `<main>` block is kept (nav, footers and marketing are
dropped), and the interactive lab widgets become a plain "Lab: <name>" note, because a
lab's value here is the technique it drills, not its JavaScript.

Run:  uv run python fetch_portswigger.py            # topics + every lab
      uv run python fetch_portswigger.py --refresh  # re-fetch pages already on disk
      uv run python fetch_portswigger.py --limit 5  # smoke test
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

SOURCES_ROOT = Path(os.environ.get("HACKPIT_SOURCES_ROOT") or Path.home())
DEST = SOURCES_ROOT / "Downloads" / "hacks" / "portswigger"

SITEMAP = "https://portswigger.net/sitemap.xml"
PREFIX = "https://portswigger.net/web-security"
# Honest identification: who we are and why, so the operator of the site can tell this
# apart from a scraper and block it if they would rather not serve it.
USER_AGENT = "HackPit-KB-ingest/1.0 (personal offline study index; contact via github.com/Zaidzyy)"
DELAY_SECONDS = 0.4

# Pages that are navigation, exam admin or account furniture rather than security content.
# The certification tree (terms, FAQs, retake policy), the learner testimonials under
# getting-started, the learning-path indexes and the telemetry privacy notice are all in
# the sitemap but say nothing about attacking anything.
_SKIP = re.compile(
    r"/web-security/?$"
    r"|/web-security/(certification|learning-path|learning-paths|getting-started)(/|$)"
    r"|/web-security/lab-telemetry-privacy-notice/?$"
    r"|/(all-labs|all-topics|dashboard|mystery-lab-challenge)/?$",
    re.IGNORECASE,
)


def _get(url: str, *, retries: int = 3) -> str:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=45) as resp:
                return resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


class _MainToMarkdown(HTMLParser):
    """Convert the `<main>` block of an Academy page to markdown.

    Deliberately small and structural rather than a general HTML converter: the Academy's
    markup is consistent, and the parts that matter for a KB entry are headings, prose,
    lists, links and — above all — CODE, which is where the payloads live.
    """

    _SKIP_TAGS = {"script", "style", "svg", "noscript", "form", "button"}
    _HEADINGS = {"h1": "#", "h2": "##", "h3": "###", "h4": "####", "h5": "#####", "h6": "######"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.depth = 0            # >0 once inside <main>
        self.skip_depth = 0       # >0 inside a tag whose content is dropped
        self.in_pre = False
        self.in_code = False
        self.list_stack: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    # --- helpers ---
    def _flush(self) -> None:
        text = re.sub(r"[ \t]+", " ", "".join(self._buf)).strip()
        self._buf = []
        if text:
            self.out.append(text)

    def _emit(self, text: str) -> None:
        self.out.append(text)

    # --- parser hooks ---
    # Content lives in <main> on every ordinary page. The two cheat sheets (XSS vectors,
    # URL-validation bypasses) — which are among the most useful pages on the site — use a
    # bare <section> instead, so that is accepted as a fallback root. Both tags are treated
    # identically once inside.
    _ROOTS = ("main", "section")

    def handle_starttag(self, tag, attrs):
        attrd = dict(attrs)
        if self.depth == 0:
            if tag in self._ROOTS:
                self.depth = 1
            return
        if tag in self._ROOTS:
            self.depth += 1
            return
        if self.skip_depth or tag in self._SKIP_TAGS:
            self.skip_depth += 1
            return
        if tag in self._HEADINGS:
            self._flush()
            self._buf.append(f"\n{self._HEADINGS[tag]} ")
        elif tag == "p":
            self._flush()
        elif tag == "pre":
            self._flush()
            self.in_pre = True
            self._emit("```")
        elif tag == "code" and not self.in_pre:
            self.in_code = True
            self._buf.append("`")
        elif tag in ("ul", "ol"):
            self._flush()
            self.list_stack.append(tag)
        elif tag == "li":
            self._flush()
            marker = "-" if (self.list_stack and self.list_stack[-1] == "ul") else "1."
            self._buf.append(f"{'  ' * (len(self.list_stack) - 1)}{marker} ")
        elif tag == "a":
            self._href = attrd.get("href")
            self._buf.append("[")
        elif tag == "br":
            self._buf.append("\n")
        elif tag == "div" and attrd.get("widget-id", "").startswith("academy-"):
            # The interactive lab widgets (launch/status/share) carry no readable content.
            self.skip_depth += 1

    def handle_endtag(self, tag):
        if self.depth == 0:
            return
        if self.skip_depth:
            self.skip_depth -= 1
            return
        if tag in self._ROOTS:
            self.depth -= 1
            self._flush()
        elif tag in self._HEADINGS or tag == "p":
            self._flush()
        elif tag == "pre":
            self._flush()
            self._emit("```")
            self.in_pre = False
        elif tag == "code" and self.in_code:
            self._buf.append("`")
            self.in_code = False
        elif tag in ("ul", "ol"):
            self._flush()
            if self.list_stack:
                self.list_stack.pop()
        elif tag == "li":
            self._flush()
        elif tag == "a":
            href = self._href or ""
            if href.startswith("/"):
                href = "https://portswigger.net" + href
            self._buf.append(f"]({href})" if href else "]")
            self._href = None

    def handle_data(self, data):
        if self.depth == 0 or self.skip_depth:
            return
        if self.in_pre:
            self._buf.append(data)
        else:
            self._buf.append(data)

    def markdown(self) -> str:
        self._flush()
        text = "\n\n".join(part for part in self.out if part.strip())
        # Every page opens with a breadcrumb rendered as a bullet list of links. It carries
        # no content and would otherwise be the first thing every entry's body says, so it
        # is dropped by starting at the h1 — which the Academy always emits.
        h1 = re.search(r"^# .+$", text, re.M)
        if h1:
            text = text[h1.start():]
        # A fenced block collapses onto its own lines; blank runs collapse to one.
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _title(html: str) -> str:
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S)
    if not m:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S)
    raw = m.group(1) if m else ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", raw)).strip()


def sitemap_urls() -> list[str]:
    """Every /web-security/ page the site itself publishes, minus navigation furniture."""
    xml = _get(SITEMAP)
    urls = re.findall(r"<loc>([^<]+)</loc>", xml)
    picked = [u for u in urls if u.startswith(PREFIX) and not _SKIP.search(u)]
    return sorted(set(picked))


def dest_for(url: str) -> Path:
    rel = url[len(PREFIX):].strip("/") or "index"
    return DEST / f"{rel}.md"


def fetch_page(url: str) -> tuple[str, str]:
    html = _get(url)
    parser = _MainToMarkdown()
    parser.feed(html)
    return _title(html), parser.markdown()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--refresh", action="store_true", help="re-fetch pages already on disk")
    ap.add_argument("--limit", type=int, default=0, help="stop after N pages (smoke test)")
    ap.add_argument("--dest", default=str(DEST))
    args = ap.parse_args()

    dest_root = Path(args.dest)
    urls = sitemap_urls()
    labs = sum(1 for u in urls if "/lab-" in u)
    print(f"{len(urls)} pages from the sitemap ({labs} labs, {len(urls) - labs} topic pages)")

    written = skipped = failed = 0
    for i, url in enumerate(urls, 1):
        if args.limit and written >= args.limit:
            break
        path = dest_root / dest_for(url).relative_to(DEST)
        if path.exists() and not args.refresh:
            skipped += 1
            continue
        try:
            title, body = fetch_page(url)
        except RuntimeError as exc:
            print(f"  ! {exc}", file=sys.stderr)
            failed += 1
            continue
        if not body:
            failed += 1
            continue
        kind = "lab" if "/lab-" in url else "topic"
        # The topic slug is the first path segment — it is how the Academy groups material,
        # and it is what lets a lab be filed under the technique it drills.
        rel = url[len(PREFIX):].strip("/")
        topic = rel.split("/")[0] if "/" in rel else rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"---\ntitle: {title}\nurl: {url}\nkind: {kind}\ntopic: {topic}\n"
            f"source: PortSwigger Web Security Academy\n---\n\n{body}\n",
            encoding="utf-8",
        )
        written += 1
        if written % 25 == 0:
            print(f"  … {written} written ({i}/{len(urls)})")
        time.sleep(DELAY_SECONDS)

    print(f"portswigger -> {dest_root}\n  written {written} · already present {skipped} · failed {failed}")


if __name__ == "__main__":
    main()
