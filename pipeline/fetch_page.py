"""Fetch INDIVIDUAL web pages into `sources/pages/`, for sources that are one post.

WHY A THIRD FETCHER, AND WHY IT IS THIS SMALL
`fetch_portswigger.py` and `fetch_gitbook.py` both turn a *site* into a local tree, driven by
that site's sitemap. Neither fits a source that is a single blog post: there is no index to
resolve and no tree to mirror, and pointing a sitemap-driven fetcher at one URL would pull the
whole blog. So this does the one missing shape — fetch exactly the URLs named, nothing else.

It deliberately reuses `fetch_gitbook`'s `robots_verdict`, `_get` and HTML->markdown converter
rather than restating them. The politeness rules are a property of this repo, not of GitBook,
and a second copy of them is a second place for them to drift.

WHAT DIFFERS FROM THE GITBOOK CONVERTER
Only the root tag. GitBook always emits `<main>`; a static-site blog may wrap the post in
`<article>` or a bare `<section>` instead, so the accepted roots are widened. Nav, header and
footer chrome are still dropped by the inherited skip-tag set, so the widening admits a page's
intro block at worst rather than the whole template.

Nothing fetched here is committed: `sources/` is gitignored, D21 governs what may be written
from it (distil, never parrot), and the tree is deleted when the batch closes.

Run:  python fetch_page.py https://example.com/blog/post
      python fetch_page.py --name my-post https://example.com/blog/post
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.parse
from pathlib import Path

from fetch_gitbook import DELAY_SECONDS, SOURCES_ROOT, _get, _MainToMarkdown, _title, robots_verdict

DEST_ROOT = SOURCES_ROOT / "sources" / "pages"


class _PageToMarkdown(_MainToMarkdown):
    """The GitBook converter with a widened set of root tags."""

    # `section` is here because a Jekyll/Hugo post template often has no `<main>` or
    # `<article>` at all — parzival.sh wraps the post in `<section class="single">`. Nav and
    # footer chrome is dropped by the inherited `_SKIP_TAGS`, so widening the root costs a
    # page's intro block at worst, where dropping `section` costs the whole post.
    _ROOT_TAGS = ("main", "article", "section")

    def handle_starttag(self, tag, attrs):  # noqa: D102 - see class docstring
        super().handle_starttag("main" if tag in self._ROOT_TAGS else tag, attrs)

    def handle_endtag(self, tag):  # noqa: D102
        super().handle_endtag("main" if tag in self._ROOT_TAGS else tag)


def _slug(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    rel = (parts.path or "").strip("/").replace("/", "-")
    host = parts.netloc.replace(".", "-")
    return re.sub(r"[^a-z0-9._-]+", "-", f"{host}-{rel}".lower()).strip("-") or host


def fetch(url: str) -> tuple[str, str]:
    """(title, markdown) for one page. Raises RuntimeError if the fetch fails."""
    html = _get(url)
    parser = _PageToMarkdown()
    parser.feed(html)
    return _title(html), parser.markdown()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("urls", nargs="+", help="page URL(s) to fetch")
    ap.add_argument("--name", help="output stem (single URL only); default is derived from the URL")
    ap.add_argument("--dest", default=str(DEST_ROOT))
    ap.add_argument("--refresh", action="store_true", help="re-fetch pages already on disk")
    args = ap.parse_args()

    if args.name and len(args.urls) > 1:
        sys.exit("--name applies to a single URL")

    dest_root = Path(args.dest)
    written = skipped = failed = 0
    for url in args.urls:
        ok, why = robots_verdict(url)
        print(f"{url}\n  robots: {why}")
        if not ok:
            print("  SKIPPED - not fetched.")
            failed += 1
            continue
        path = dest_root / f"{args.name or _slug(url)}.md"
        if path.exists() and not args.refresh:
            print(f"  already on disk: {path}")
            skipped += 1
            continue
        try:
            title, body = fetch(url)
        except RuntimeError as exc:
            print(f"  ! {exc}", file=sys.stderr)
            failed += 1
            continue
        if not body:
            print("  ! empty extraction - no <main> or <article> root found")
            failed += 1
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"---\ntitle: {title}\nurl: {url}\n---\n\n{body}\n", encoding="utf-8"
        )
        print(f"  -> {path}  ({len(body):,} chars, title={title!r})")
        written += 1
        time.sleep(DELAY_SECONDS)

    print(f"pages: written {written} · already present {skipped} · failed {failed}")


if __name__ == "__main__":
    main()
