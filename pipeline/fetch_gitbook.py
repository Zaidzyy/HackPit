"""Fetch a GitBook note-space into a local source tree, the same way `fetch_portswigger.py`
turns the Web Security Academy into one.

WHY THIS EXISTS
Most KB sources arrive as a directory of markdown that `consolidate.py` folds in. A GitBook
space is a website, so this script does the one thing the pipeline cannot: turn it into that
same on-disk shape. Nothing downstream needs to know a website was involved.

WHAT MAKES IT POLITE, AND WHY EACH PART MATTERS
* URLs come from the space's own **sitemap**, never from crawling links. GitBook publishes a
  `sitemap.xml` that is a *sitemap index* pointing at `sitemap-pages.xml`; this resolves that
  indirection per space rather than assuming a path, because the two spaces that moved it
  would otherwise be silently fetched as 404s.
* Pages are taken as **markdown the publisher already offers**: GitBook serves every page at
  `<url>.md` and advertises it in-page next to an `llms.txt` index. That is the format the
  site chose to hand to machines, so it is the one we ask for — it is a third the bytes of
  the HTML, arrives with real ```lang fences, and carries none of the nav chrome. The HTML
  path below is the fallback for a space that does not serve it.
* `robots.txt` is checked and **honoured before a single page is requested** — see
  `robots_verdict`, which refuses on a `Disallow: /` for us *and* on an explicit AI-crawler
  opt-out. A space whose operator has said no is recorded as a skip, not fetched anyway.
* Requests are serialised with a delay and carry an honest User-Agent naming what this is.
* Pages are fetched **once to disk**. Iterating on the distillation re-reads the disk copy;
  it never re-hammers the site. `--refresh` is the deliberate opt-in to re-fetch.

WHAT IT KEEPS, AND WHAT THAT MEANS FOR THE KB
Only the `<main>` block — GitBook's nav tree, page-footer chrome and "powered by" furniture
are dropped. What lands on disk is READING MATERIAL, not entry text: these spaces are
individuals' personal certification notes and are copyrighted exactly like any other writeup.
D21 governs what happens next — distil, never parrot. Nothing fetched here is committed;
`sources/` is gitignored and the tree is deleted after the batch.

Run:  python fetch_gitbook.py --space checklist-gokul
      python fetch_gitbook.py --space ecpptv3 --under readme/ecpptv3/active-directory
      python fetch_gitbook.py --space ecpptv3 --limit 2      # smoke test
      python fetch_gitbook.py --list                          # index only, fetches no pages
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

SOURCES_ROOT = Path(os.environ.get("HACKPIT_SOURCES_ROOT") or Path(__file__).resolve().parents[1])
DEST_ROOT = SOURCES_ROOT / "sources" / "gitbooks"

# The seven spaces this batch was pointed at. Kept complete rather than pruned to the ones
# actually fetched, so the skip decisions stay auditable next to the URLs they applied to.
SPACES = {
    "ecpptv3": "https://dev-angelist.gitbook.io/ecpptv3-ptp-notes",
    "ecpptv2": "https://dev-angelist.gitbook.io/ecpptv2-ptp-notes",
    "crtp-devangelist": "https://dev-angelist.gitbook.io/crtp-notes",
    "crtp-teamanon": "https://team-anonymous.gitbook.io/certified-red-team-professional-crtp-notes",
    "crtp-dudisamarel": "https://dudisamarel.gitbook.io/crtp-notes",
    "oscp-mqt": "https://mqt.gitbook.io/oscp-notes",
    "checklist-gokul": "https://gokulkarthik.gitbook.io/pentesting-checklist",
}

USER_AGENT = "HackPit-KB-ingest/1.0 (personal offline study index; contact via github.com/Zaidzyy)"
DELAY_SECONDS = 0.6

# Crawler names whose blanket `Disallow: /` tells us the operator does not want automated
# collection for machine consumption. We are not any of these bots, but the signal is about
# intent rather than user-agent string, and the cost of honouring it is one skipped space.
_AI_AGENTS = {
    "claudebot", "gptbot", "ccbot", "google-extended", "applebot-extended",
    "bytespider", "amazonbot", "meta-externalagent", "anthropic-ai",
}


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


def robots_verdict(base: str) -> tuple[bool, str]:
    """(may_fetch, reason) for a space, from its host's robots.txt.

    Two independent grounds for refusal, both checked before anything is fetched:
    a `Disallow` that covers our path under the `*` group, and an explicit opt-out aimed at
    AI crawlers (either a blanket `Disallow: /` for one of them, or `ai-train=no` in the
    Cloudflare `Content-Signal` header). The second is not binding on a non-bot fetch, but a
    site that has spelled out "not for machine consumption" has said what it wants.
    """
    parts = urllib.parse.urlsplit(base)
    try:
        body = _get(f"{parts.scheme}://{parts.netloc}/robots.txt")
    except RuntimeError:
        return True, "no robots.txt served"

    path = parts.path or "/"
    agents: list[str] = []
    star_disallows: list[str] = []
    ai_optout: list[str] = []
    signals: list[str] = []

    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            # A blank line ends a group; robots.txt in the wild is loose about this, so
            # consecutive User-agent lines are treated as one group, which is the spec.
            if agents and (star_disallows or ai_optout or signals):
                agents = []
            agents.append(value.lower())
        elif field == "disallow" and agents:
            if "*" in agents and value and path.startswith(value.rstrip("*")):
                star_disallows.append(value)
            if value == "/" and any(a in _AI_AGENTS for a in agents):
                ai_optout.extend(a for a in agents if a in _AI_AGENTS)
        elif field == "content-signal":
            signals.append(value.lower())

    if star_disallows:
        return False, f"robots.txt Disallow {star_disallows[0]!r} covers {path}"
    no_train = [s for s in signals if re.search(r"ai-train\s*=\s*no", s)]
    if ai_optout or no_train:
        why = []
        if ai_optout:
            why.append("Disallow:/ for " + ", ".join(sorted(set(ai_optout))))
        if no_train:
            why.append("Content-Signal ai-train=no")
        return False, "operator opted out of machine collection (" + "; ".join(why) + ")"
    return True, "allowed"


def sitemap_urls(base: str) -> list[str]:
    """Every page URL the space itself publishes.

    `sitemap.xml` on a GitBook space is a *sitemap index* whose single entry is
    `sitemap-pages.xml`. Resolve rather than assume — a space that changes the inner name
    still works, and we never invent a URL we were not offered.
    """
    seen: set[str] = set()
    queue = [base.rstrip("/") + "/sitemap.xml"]
    pages: list[str] = []
    while queue:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        xml = _get(url)
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml)
        if "<sitemapindex" in xml:
            queue.extend(locs)
        else:
            pages.extend(u for u in locs if u.startswith(base.rstrip("/")))
        time.sleep(DELAY_SECONDS)
    return sorted(set(pages))


class _MainToMarkdown(HTMLParser):
    """Convert a GitBook page's `<main>` block to markdown.

    Structural rather than a general HTML converter, for the same reason the PortSwigger one
    is: what a KB entry needs from these pages is headings, prose, lists and above all CODE.
    GitBook wraps every code block in `<pre>`, so those survive intact.
    """

    _SKIP_TAGS = {"script", "style", "svg", "noscript", "form", "button", "nav", "aside", "header", "footer"}
    _HEADINGS = {"h1": "#", "h2": "##", "h3": "###", "h4": "####", "h5": "#####", "h6": "######"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.depth = 0
        self.skip_depth = 0
        self.in_pre = False
        self.in_code = False
        self.list_stack: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def _flush(self) -> None:
        text = re.sub(r"[ \t]+", " ", "".join(self._buf)).strip()
        self._buf = []
        if text:
            self.out.append(text)

    def handle_starttag(self, tag, attrs):
        attrd = dict(attrs)
        if self.depth == 0:
            if tag == "main":
                self.depth = 1
            return
        if tag == "main":
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
            self.out.append("```")
        elif tag == "code" and not self.in_pre:
            self.in_code = True
            self._buf.append("`")
        elif tag in ("ul", "ol"):
            self._flush()
            self.list_stack.append(tag)
        elif tag == "li":
            self._flush()
            marker = "-" if (self.list_stack and self.list_stack[-1] == "ul") else "1."
            self._buf.append(f"{'  ' * max(0, len(self.list_stack) - 1)}{marker} ")
        elif tag == "a":
            self._href = attrd.get("href")
            self._buf.append("[")
        elif tag == "br":
            self._buf.append("\n")
        elif tag == "img":
            alt = attrd.get("alt", "").strip()
            if alt:
                self._buf.append(f"[image: {alt}]")

    def handle_endtag(self, tag):
        if self.depth == 0:
            return
        if self.skip_depth:
            self.skip_depth -= 1
            return
        if tag == "main":
            self.depth -= 1
            self._flush()
        elif tag in self._HEADINGS or tag == "p":
            self._flush()
        elif tag == "pre":
            self._flush()
            self.out.append("```")
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
            self._buf.append(f"]({href})" if href else "]")
            self._href = None

    def handle_data(self, data):
        if self.depth == 0 or self.skip_depth:
            return
        self._buf.append(data)

    def markdown(self) -> str:
        self._flush()
        text = "\n\n".join(part for part in self.out if part.strip())
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _title(html: str) -> str:
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S) or re.search(r"<title[^>]*>(.*?)</title>", html, re.S)
    raw = m.group(1) if m else ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", raw)).strip()


def rel_path(base: str, url: str) -> str:
    rel = url[len(base.rstrip("/")):].strip("/")
    return rel or "index"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--space", action="append", help="space key (repeatable); default: all")
    ap.add_argument("--list", action="store_true", help="resolve sitemaps and print the index; fetch no pages")
    ap.add_argument("--under", action="append", default=[], help="only pages whose path starts with this (repeatable)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N pages per space (smoke test)")
    ap.add_argument("--refresh", action="store_true", help="re-fetch pages already on disk")
    ap.add_argument("--dest", default=str(DEST_ROOT))
    args = ap.parse_args()

    keys = args.space or list(SPACES)
    unknown = [k for k in keys if k not in SPACES]
    if unknown:
        sys.exit(f"unknown space(s): {', '.join(unknown)}; known: {', '.join(SPACES)}")

    for key in keys:
        base = SPACES[key]
        ok, why = robots_verdict(base)
        print(f"[{key}] {base}\n  robots: {why}")
        if not ok:
            print("  SKIPPED — not fetched.")
            continue

        urls = sitemap_urls(base)
        if args.under:
            urls = [u for u in urls if any(rel_path(base, u).startswith(p) for p in args.under)]
        print(f"  {len(urls)} pages from the sitemap")
        if args.list:
            for u in urls:
                print("   ", rel_path(base, u))
            continue

        dest = Path(args.dest) / key
        written = skipped = failed = 0
        for url in urls:
            if args.limit and written >= args.limit:
                break
            path = dest / f"{rel_path(base, url)}.md"
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
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"---\ntitle: {title}\nurl: {url}\nspace: {key}\nsource: {base}\n---\n\n{body}\n",
                encoding="utf-8",
            )
            written += 1
            if written % 25 == 0:
                print(f"    … {written} written")
            time.sleep(DELAY_SECONDS)
        print(f"  -> {dest}\n  written {written} · already present {skipped} · failed {failed}")


# GitBook prepends this pointer to every markdown page. It is site furniture, not content.
_MD_BANNER = re.compile(r"^>\s*For the complete documentation index.*?\n+", re.S)


def fetch_page(url: str) -> tuple[str, str]:
    """(title, markdown) for one page, preferring the publisher's own `.md` rendering.

    A missing page is served as 200 with a `# Page Not Found` body rather than a 404, so
    that is detected explicitly — otherwise a renamed page lands on disk as a stub and gets
    triaged as if it were content.
    """
    try:
        body = _get(url.rstrip("/") + ".md")
        if not body.lstrip().startswith("# Page Not Found"):
            body = _MD_BANNER.sub("", body).strip()
            m = re.search(r"^#\s+(.+)$", body, re.M)
            return (m.group(1).strip() if m else ""), body
    except RuntimeError:
        pass  # fall through to the HTML route
    html = _get(url)
    parser = _MainToMarkdown()
    parser.feed(html)
    return _title(html), parser.markdown()


if __name__ == "__main__":
    main()
