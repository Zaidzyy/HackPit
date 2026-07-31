"""Fetch a PRIORITISED SUBSET of 0xdf's machine writeups into a local source tree.

WHY THIS EXISTS
`ingest_exploitation_writeups.py` keys a service+version fingerprint to the technique that
solves it, and build #8's 2.7 retrieval ranks that ahead of generic token matches. A ranker is
only as good as its corpus. 0xdf's archive is several hundred long-form writeups that each start
from a scan result and end at root — a service->technique mapping in narrative form, which is
exactly the shape the fingerprint corpus needs and the one thing cert notes never supplied.

WHAT THIS IS *NOT*
It is not a mirror. Mirroring an archive is a different act from distilling from it, and the
fetched tree is gitignored and deleted after the batch. What survives is original entries in
HackPit's voice, each crediting the writeup it was learned from by URL in `references`.
DISTIL, NEVER PARROT — see the sourcing block in `ingest_exploitation_writeups.py`.

POLITENESS — this is one person's personal blog on GitLab Pages, not a corporate docs site
* URLs come only from the site's own `sitemap.xml`, never from crawling links.
* `robots.txt` is checked on every run and honoured. It is currently 404 (no restrictions
  published); if that ever changes to disallow the post paths, `--index`/`--fetch` refuse to run
  rather than working around it.
* Requests are serialised behind a real delay (1.8s default) and carry an honest User-Agent.
* `--index` costs exactly TWO requests (sitemap + the site's own /tags/ page) and yields the
  complete post/tag map for all posts, so triage never needs a page fetch.
* Pages already on disk are skipped, so iterating on the distillation never re-hammers the site.

Run::

    python pipeline/fetch_0xdf.py --index                  # 2 requests -> index.json, no posts
    python pipeline/fetch_0xdf.py --limit 3                # smoke test
    python pipeline/fetch_0xdf.py --urls shortlist.txt     # the prioritised subset
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import urllib.robotparser
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEST = REPO_ROOT / "sources" / "0xdf"

SITE = "https://0xdf.gitlab.io"
SITEMAP = f"{SITE}/sitemap.xml"
TAGS_PAGE = f"{SITE}/tags/"
ROBOTS = f"{SITE}/robots.txt"

USER_AGENT = "HackPit-KB-ingest/1.0 (personal offline study index; contact via github.com/Zaidzyy)"
DELAY_SECONDS = 1.8  # a hobby blog on GitLab Pages - slower than the PortSwigger fetcher on purpose

_POST_RE = re.compile(r"^https://0xdf\.gitlab\.io/\d{4}/\d{2}/\d{2}/")


def _get(url: str, *, retries: int = 3) -> str:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                raise                      # a missing page is a fact, not a transient failure
            last = exc
            time.sleep(2.0 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(2.0 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def robots_allows(sample_url: str = f"{SITE}/2022/05/03/htb-antique.html") -> tuple[bool, str]:
    """Check robots.txt and honour it. A 404 means no restrictions were published.

    Returns (allowed, human-readable reason). The caller REFUSES to fetch on False - working
    around a publisher's stated preference is not on the table.
    """
    try:
        body = _get(ROBOTS)
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            return True, f"robots.txt returns {exc.code} - no restrictions published"
        return False, f"robots.txt unreadable (HTTP {exc.code}) - refusing to guess"
    except RuntimeError as exc:
        return False, f"robots.txt unreachable ({exc}) - refusing to guess"

    rp = urllib.robotparser.RobotFileParser()
    rp.parse(body.splitlines())
    for agent in (USER_AGENT, "ClaudeBot", "*"):
        if not rp.can_fetch(agent, sample_url):
            return False, f"robots.txt disallows post paths for {agent!r}"
    if re.search(r"ai-train\s*=\s*no", body, re.I):
        return False, "robots.txt carries Content-Signal: ai-train=no"
    return True, "robots.txt present and permits the post paths"


class _PostToMarkdown(HTMLParser):
    """Convert the `#postBody` block of a 0xdf post to markdown.

    Small and structural, like the PortSwigger converter. What matters for distillation is the
    headings (they name the phase: enumeration / shell / privesc), the prose that explains WHY a
    step works, and the fenced terminal output that carries the service banners and versions.
    Images, the sticky ToC and the nav furniture carry nothing and are dropped.
    """

    _SKIP_TAGS = {"script", "style", "svg", "noscript", "form", "button", "nav", "picture", "img"}
    _HEADINGS = {"h1": "#", "h2": "##", "h3": "###", "h4": "####", "h5": "#####", "h6": "######"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.depth = 0          # >0 once inside #postBody
        self.skip_depth = 0
        self.in_pre = False
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
            if attrd.get("id") == "postBody":
                self.depth = 1
            return
        if self.skip_depth:
            # still need to balance nested opens of the tag we are skipping
            if tag not in ("br", "img", "hr", "meta", "link", "source"):
                self.skip_depth += 1
            return
        if tag in self._SKIP_TAGS:
            if tag not in ("img", "source"):
                self.skip_depth += 1
            return
        if tag == "div":
            self.depth += 1
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

    def handle_endtag(self, tag):
        if self.depth == 0:
            return
        if self.skip_depth:
            self.skip_depth -= 1
            return
        if tag == "div":
            self.depth -= 1
            if self.depth == 0:
                self._flush()
            return
        if tag in self._HEADINGS or tag == "p":
            self._flush()
        elif tag == "pre":
            self._flush()
            self.out.append("```")
            self.in_pre = False
        elif tag == "code" and not self.in_pre:
            self._buf.append("`")
        elif tag in ("ul", "ol"):
            self._flush()
            if self.list_stack:
                self.list_stack.pop()
        elif tag == "li":
            self._flush()
        elif tag == "a":
            href = self._href or ""
            if href.startswith("/"):
                href = SITE + href
            self._buf.append(f"]({href})" if href else "]")
            self._href = None

    def handle_data(self, data):
        if self.depth == 0 or self.skip_depth:
            return
        self._buf.append(data)

    def markdown(self) -> str:
        self._flush()
        text = "\n\n".join(p for p in self.out if p.strip())
        return re.sub(r"\n{3,}", "\n\n", text).strip()


def sitemap_posts() -> list[str]:
    xml = _get(SITEMAP)
    urls = re.findall(r"<loc>([^<]+)</loc>", xml)
    return sorted({u for u in urls if _POST_RE.match(u)})


def tag_index() -> dict[str, dict]:
    """post-url -> {title, tags}, built from the site's OWN /tags/ page. One request for the
    whole archive's metadata, which is why triage never costs a per-post fetch."""
    html = _get(TAGS_PAGE)
    body = html[html.find('class="tags-expo-section"'):]
    parts = re.split(r'<h2 id="([^"]+)">', body)
    posts: dict[str, dict] = {}
    for i in range(1, len(parts), 2):
        tag, chunk = parts[i], parts[i + 1]
        for href, raw_title in re.findall(
                r'<a href="(/\d{4}/\d{2}/\d{2}/[^"]+)"[^>]*>(.*?)</a>', chunk, re.S):
            url = SITE + href
            title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", raw_title)).strip()
            rec = posts.setdefault(url, {"title": title, "tags": []})
            rec["tags"].append(tag)
    for rec in posts.values():
        rec["tags"] = sorted(set(rec["tags"]))
    return posts


def _title(html: str) -> str:
    m = re.search(r'<h1 class="post-title[^"]*"[^>]*>(.*?)</h1>', html, re.S) \
        or re.search(r"<title[^>]*>(.*?)</title>", html, re.S)
    raw = m.group(1) if m else ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", raw)).strip()


def dest_for(url: str, root: Path) -> Path:
    return root / (url[len(SITE):].strip("/").replace("/", "-").removesuffix(".html") + ".md")


def main() -> None:
    ap = argparse.ArgumentParser(description="Fetch a prioritised subset of 0xdf writeups.")
    ap.add_argument("--index", action="store_true",
                    help="write index.json (sitemap + tag map) and stop - 2 requests, no posts")
    ap.add_argument("--urls", help="file of post URLs, one per line (# comments allowed)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N pages (smoke test)")
    ap.add_argument("--refresh", action="store_true", help="re-fetch pages already on disk")
    ap.add_argument("--dest", default=str(DEST))
    args = ap.parse_args()

    allowed, reason = robots_allows()
    print(f"robots: {reason}")
    if not allowed:
        print("REFUSING TO FETCH - the publisher's robots.txt does not permit this.", file=sys.stderr)
        sys.exit(2)

    root = Path(args.dest)
    root.mkdir(parents=True, exist_ok=True)

    if args.index:
        time.sleep(DELAY_SECONDS)
        posts = sitemap_posts()
        time.sleep(DELAY_SECONDS)
        meta = tag_index()
        merged = {u: meta.get(u, {"title": "", "tags": []}) for u in posts}
        for u, rec in meta.items():           # tag page can list a post the sitemap omits
            merged.setdefault(u, rec)
        (root / "index.json").write_text(json.dumps(merged, indent=1), encoding="utf-8")
        tags = {t for r in merged.values() for t in r["tags"]}
        print(f"index -> {root / 'index.json'}\n  {len(merged)} posts · {len(tags)} distinct tags")
        return

    if args.urls:
        urls = [ln.strip() for ln in Path(args.urls).read_text(encoding="utf-8").splitlines()]
        urls = [u for u in urls if u and not u.startswith("#")]
    else:
        urls = sitemap_posts()

    written = skipped = failed = 0
    for url in urls:
        if args.limit and written >= args.limit:
            break
        path = dest_for(url, root)
        if path.exists() and not args.refresh:
            skipped += 1
            continue
        try:
            html = _get(url)
        except (RuntimeError, urllib.error.HTTPError) as exc:
            print(f"  ! {url}: {exc}", file=sys.stderr)
            failed += 1
            continue
        parser = _PostToMarkdown()
        parser.feed(html)
        body = parser.markdown()
        if not body:
            print(f"  ! {url}: no #postBody content extracted", file=sys.stderr)
            failed += 1
            continue
        # the post's own tag list: <a href="/tags#telnet" class="post-tag">telnet</a>
        tags = re.findall(r'<a href="/tags[/#][^"]*"[^>]*class="post-tag"[^>]*>([^<]+)</a>', html)
        path.write_text(
            f"---\ntitle: {_title(html)}\nurl: {url}\ntags: {', '.join(tags)}\n"
            f"source: 0xdf hacks stuff (https://0xdf.gitlab.io)\n---\n\n{body}\n",
            encoding="utf-8",
        )
        written += 1
        if written % 10 == 0:
            print(f"  … {written} written")
        time.sleep(DELAY_SECONDS)

    print(f"0xdf -> {root}\n  written {written} · already present {skipped} · failed {failed}")


if __name__ == "__main__":
    main()
