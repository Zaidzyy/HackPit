"""Route B — the additive corpus ingester (D11 / D12).

The assessment's headline source-usage finding was that `ingest.py` and
`ingest_notes.py` both glob `**/*.md`, so **every non-markdown file in every source
tree was invisible to the pipeline**. PayloadsAllTheThings' 66 `.txt` payload lists,
the shodan dork list and ~22 `oscp_tools` scripts were read as *explanations* and had
their *payloads* discarded — backwards for bug bounty.

This module is **Route B**: a targeted ingester over only the missing files, run
*additively* on top of the built KB. It is deliberately NOT part of the
`ingest -> consolidate -> curate -> authored -> embed` chain, because re-running that
chain reverts downstream enrichment (see the pipeline build-order note) and rewrites
15 MB of `entries.jsonl` for no reason.

THE TWO GUARANTEES
------------------
1. **Existing entries are never rewritten.** Lines this ingester does not own are
   copied through as raw *bytes* — they are never JSON round-tripped, so a
   float, a key order or an escape sequence cannot drift.
2. **Idempotent.** Every line this ingester writes carries ``meta.corpus_ingest``.
   A re-run drops exactly those lines and regenerates them from source, so running
   twice yields a byte-identical file (asserted by ``test_corpora.py``).

THE THREE SHAPES (§4.4 — "a checklist is a sequence, a dork list is a set, a payload
collection is a corpus"; all three were previously forced through a technique-shaped
schema and collapsed):

* ``payload-set`` — a corpus of payloads for one vulnerability class.
* ``dork-list``   — a set of search queries (shodan, github).
* ``checklist``   — an ordered sequence of checks.

ENTRY + SIDECAR. A payload corpus is 3.5 MB across 66 files; the largest single file
is 1.8 MB. Inlining that would triple `entries.jsonl` and let one 40,000-line entry
dominate BM25. So each corpus becomes a normal, searchable, retrievable KB entry
holding a *capped representative excerpt*, while the **full list is written verbatim
to a sidecar** under ``data/kb/payloads/`` — which the sandboxes mount read-only at
``/payloads``, so ffuf/wfuzz and the HTTP repeater can point straight at it. The
payloads are findable by the planner *and* usable at runtime.

`oscp_tools` is handled separately: those are standalone tool files, not knowledge,
so they land in the **Scripts Arsenal** via ``data/kb/toolfiles.json`` (consumed by
``scripts_index.py``) rather than in the KB. Windows-only binaries are kept and
marked ``platform: windows`` per D9 — useful for planning and write-ups, never
proposed as runnable.

Run::

    uv run python pipeline/ingest_corpora.py --dry-run
    uv run python pipeline/ingest_corpora.py

Then ``uv run python pipeline/embed.py`` (incremental — only the new entries
vectorise) and ``uv run python pipeline/scripts_index.py`` to fold the tool files
into the arsenal. Restart the backend to serve the new counts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from schema import Entry  # noqa: E402  (local module, path set above)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
# The three DERIVED artefacts, named relative to the KB rather than to the repo. `--kb` used
# to redirect only entries.jsonl while these three kept writing into data/kb regardless, so
# "run the ingester somewhere else" quietly still rewrote production. Every path under
# /data/ is gitignored — none of them has a restore path but a rebuild — so a run pointed at
# a copy has to be a run that touches nothing but the copy. Outputs now follow their KB.
PAYLOAD_DIRNAME = "payloads"
TOOLFILES_NAME = "toolfiles.json"
REPORT_NAME = "corpora_report.json"
PAYLOAD_DIR = DEFAULT_KB.parent / PAYLOAD_DIRNAME
TOOLFILES_OUT = DEFAULT_KB.parent / TOOLFILES_NAME
REPORT_OUT = DEFAULT_KB.parent / REPORT_NAME

# Raw source trees live OUTSIDE the repo (gitignored, never committed). Same
# convention as consolidate.py: default under the current user's home so a fresh
# clone carries no hardcoded username; override with HACKPIT_SOURCES_ROOT.
SOURCES_ROOT = Path(os.environ.get("HACKPIT_SOURCES_ROOT") or Path.home())


def _src(*parts: str) -> Path:
    return SOURCES_ROOT.joinpath(*parts)


DEFAULT_PATT = _src("Downloads", "hacks", "new resources", "PayloadsAllTheThings")
DEFAULT_SHODAN = _src("Downloads", "hacks", "new resources", "shodan-dorks")
DEFAULT_OSCP_TOOLS = _src("Downloads", "hacks", "new resources", "oscp_tools")

# The marker every line this ingester owns carries. Load-bearing for idempotency.
CORPUS_MARK = "corpus_ingest"

# Where the sandboxes mount the payload sidecars (docker-compose.yml, read-only).
CONTAINER_PAYLOAD_DIR = "/payloads"

# Body excerpt caps — the entry is a searchable *description* of the corpus, not
# the corpus. The full list always lives in the sidecar.
SAMPLE_LINES = 40
SAMPLE_CHARS = 3500


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str, cap: int = 60) -> str:
    s = _SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return s[:cap].strip("-")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_read_bytes(path: Path, root: Path) -> tuple[bytes | None, str]:
    """Read ``path``, falling back to git when the working copy is unreadable.

    Both source trees are git repos, and a meaningful slice of them cannot be opened:
    20 of 70 `oscp_tools` files (PowerView, linpeas, LinEnum, the PEASS binaries — the
    recognisable hacktools) fail with EACCES/EINVAL because the host AV holds them
    locked in place, and OneDrive dehydration causes the same symptom elsewhere in
    these trees. Both are environment artifacts, not missing content: ``git show`` on
    the committed blob returns the real bytes.

    Returns ``(data, how)`` where *how* is ``"disk"``, ``"git"`` or ``"failed"``.
    """
    try:
        return path.read_bytes(), "disk"
    except OSError:
        pass
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return None, "failed"
    try:
        import subprocess

        out = subprocess.run(
            ["git", "-C", str(root), "show", f"HEAD:{rel}"],
            capture_output=True, timeout=60,
        )
        if out.returncode == 0 and out.stdout:
            return out.stdout, "git"
    except (OSError, subprocess.SubprocessError):
        pass
    return None, "failed"


def all_files(root: Path, suffix: str) -> list[Path]:
    """Every ``*<suffix>`` file under ``root`` — the UNION of rglob and ``git ls-files``.

    rglob alone is not sufficient on these trees. A OneDrive-dehydrated file can vanish
    from directory listings entirely, so rglob never yields it and the loss is SILENT
    (it measured 64 of PayloadsAllTheThings' 66 `.txt` files here). The markdown
    ingesters hit the same thing and solved it the same way; git is the authority on
    what the tree actually contains, and :func:`safe_read_bytes` then recovers the
    bytes for anything the working copy will not open.
    """
    found: dict[str, Path] = {}
    for p in root.rglob(f"*{suffix}"):
        rel = p.relative_to(root)
        if ".git" in rel.parts or not p.is_file():
            continue
        found[rel.as_posix()] = p
    try:
        import subprocess

        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", f"*{suffix}"],
            capture_output=True, text=True, timeout=60,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                rel = line.strip()
                if rel and rel not in found:
                    found[rel] = root / rel
    except (OSError, subprocess.SubprocessError):
        pass
    return [found[k] for k in sorted(found)]


def _lines_from(raw: bytes) -> list[str]:
    """Payload corpora are not guaranteed UTF-8 (fuzzing lists carry raw high bytes).

    The sidecar keeps the bytes verbatim; only the excerpt decodes leniently — a
    mojibake sample line is cosmetic, a corrupted payload is not.
    """
    return [ln for ln in raw.decode("utf-8", errors="replace").splitlines() if ln.strip()]


def _excerpt(lines: list[str]) -> tuple[str, bool]:
    """A capped, fenced sample of the corpus. Returns (text, truncated)."""
    out: list[str] = []
    used = 0
    for ln in lines[:SAMPLE_LINES]:
        if used + len(ln) > SAMPLE_CHARS:
            break
        out.append(ln)
        used += len(ln) + 1
    return "\n".join(out), len(out) < len(lines)


# --------------------------------------------------------------------------- #
# PayloadsAllTheThings — the class map
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ClassSpec:
    """How one PATT attack folder maps into the KB."""

    category: str
    tags: tuple[str, ...]
    # A usage recipe. `{p}` is substituted with the container payload path.
    recipe: str
    kind: str = "payload-set"


_GENERIC = ClassSpec(
    "web", ("fuzzing", "payloads"),
    "ffuf -w {p}:FUZZ -u 'http://<target>/?param=FUZZ' -mc all -ac",
)

PATT_CLASSES: dict[str, ClassSpec] = {
    "Directory Traversal": ClassSpec(
        "web", ("directory-traversal", "path-traversal", "lfi", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/index.php?file=FUZZ' -mc all -ac",
    ),
    "File Inclusion": ClassSpec(
        "web", ("file-inclusion", "lfi", "rfi", "path-traversal", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/index.php?page=FUZZ' -mc all -ac",
    ),
    "XSS Injection": ClassSpec(
        "web", ("xss", "cross-site-scripting", "fuzzing"),
        "dalfox url 'http://<target>/search?q=FUZZ' --custom-payload {p}",
    ),
    "SQL Injection": ClassSpec(
        "web", ("sqli", "sql-injection", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/item?id=FUZZ' -mc all -ac",
    ),
    "NoSQL Injection": ClassSpec(
        "web", ("nosql-injection", "mongodb", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/api/user?q=FUZZ' -mc all -ac",
    ),
    "Command Injection": ClassSpec(
        "web", ("command-injection", "rce", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/ping?host=127.0.0.1FUZZ' -mc all -ac",
    ),
    "LDAP Injection": ClassSpec(
        "web", ("ldap-injection", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/login?user=FUZZ' -mc all -ac",
    ),
    "XXE Injection": ClassSpec(
        "web", ("xxe", "xml", "fuzzing"),
        "# body payloads — feed one per request:\n"
        "ffuf -w {p}:FUZZ -X POST -H 'Content-Type: application/xml' "
        "-d 'FUZZ' -u 'http://<target>/api/parse' -mc all -ac",
    ),
    "CRLF Injection": ClassSpec(
        "web", ("crlf-injection", "header-injection", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/?redirect=FUZZ' -mc all -ac",
    ),
    "Open Redirect": ClassSpec(
        "web", ("open-redirect", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/login?next=FUZZ' -mc 301,302,303,307,308",
    ),
    "Server Side Include Injection": ClassSpec(
        "web", ("ssi", "esi", "injection", "fuzzing"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/?name=FUZZ' -mc all -ac",
    ),
    "Web Cache Deception": ClassSpec(
        "web", ("web-cache-deception", "cache-poisoning", "header-fuzzing"),
        "ffuf -w {p}:FUZZ -H 'FUZZ: hackpit' -u 'http://<target>/' -mc all -ac",
    ),
    "Insecure Management Interface": ClassSpec(
        "web", ("management-interface", "actuator", "content-discovery"),
        "ffuf -w {p}:FUZZ -u 'http://<target>/FUZZ' -mc 200,401,403",
    ),
    "Insecure Source Code Management": ClassSpec(
        "recon", ("dorks", "source-code-leak", "github"),
        "# paste into GitHub code search, one query at a time:\n"
        "#   https://github.com/search?type=code&q=<org>+<query>",
        kind="dork-list",
    ),
    "API Key Leaks": ClassSpec(
        "web", ("api-keys", "secrets", "asp-net", "machinekey"),
        "# reference corpus — look a captured value up rather than fuzzing with it:\n"
        "grep -F '<captured-value>' {p}",
    ),
}


def _patt_class(rel: Path) -> tuple[str, ClassSpec]:
    """The attack-folder name and its ClassSpec for a PATT file."""
    folder = rel.parts[0] if rel.parts else ""
    return folder, PATT_CLASSES.get(folder, _GENERIC)


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
@dataclass
class Corpus:
    """One discovered payload/dork corpus, before it becomes an Entry."""

    entry_id: str
    title: str
    source: str
    source_label: str
    category: str
    subcategory: str | None
    tags: list[str]
    kind: str
    recipe: str
    rel_path: str
    abs_path: Path
    lines: list[str]
    raw: bytes
    read_via: str = "disk"


@dataclass
class Discovery:
    corpora: list[Corpus] = field(default_factory=list)
    flagged: list[dict] = field(default_factory=list)


def discover_patt(root: Path) -> Discovery:
    """PATT's `.txt` payload lists, one corpus per file (payload-level granularity)."""
    d = Discovery()
    if not root.is_dir():
        d.flagged.append({"file": str(root), "reason": "PATT source path not found"})
        return d

    for path in all_files(root, ".txt"):
        rel = path.relative_to(root)
        folder, spec = _patt_class(rel)
        raw, how = safe_read_bytes(path, root)
        if raw is None:
            d.flagged.append({"file": str(rel), "reason": "unreadable on disk and in git"})
            continue
        lines = _lines_from(raw)
        # Two lines is a legitimate corpus here — SQLi_Polyglots.txt is two polyglots
        # that each cover a dozen contexts. Only a single-line file is a stub.
        if len(lines) < 2:
            d.flagged.append({"file": str(rel), "reason": f"only {len(lines)} payload lines"})
            continue

        stem = path.stem
        # A file whose own name says "dork" is a dork list wherever it sits.
        kind = "dork-list" if "dork" in stem.lower() else spec.kind
        eid = f"{kind}-{_slug(folder)}-{_slug(stem)}"
        noun = "dorks" if kind == "dork-list" else "payloads"
        d.corpora.append(Corpus(
            entry_id=eid,
            title=f"{folder} — {stem} ({len(lines):,} {noun})",
            source="payloadsallthethings",
            source_label="PayloadsAllTheThings",
            category=spec.category,
            subcategory=folder,
            tags=sorted({*spec.tags, kind, _slug(folder)}),
            kind=kind,
            recipe=spec.recipe,
            rel_path=str(rel).replace("\\", "/"),
            abs_path=path,
            lines=lines,
            raw=raw,
            read_via=how,
        ))
    return d


def discover_shodan(root: Path) -> Discovery:
    """The shodan dork list — a *set* of queries, not a technique."""
    d = Discovery()
    path = root / "dorks.txt"
    if not path.is_file():
        d.flagged.append({"file": str(path), "reason": "shodan dorks.txt not found"})
        return d
    raw, how = safe_read_bytes(path, root)
    if raw is None:
        d.flagged.append({"file": "dorks.txt", "reason": "unreadable on disk and in git"})
        return d
    lines = _lines_from(raw)
    d.corpora.append(Corpus(
        entry_id="dork-list-shodan-dorks",
        title=f"Shodan dork list ({len(lines):,} queries)",
        source="shodan-dorks",
        source_label="shodan-dorks",
        category="recon",
        subcategory="shodan",
        tags=["dorks", "dork-list", "shodan", "recon", "attack-surface"],
        kind="dork-list",
        recipe=(
            "# paste a query into https://www.shodan.io/search, or with an API key:\n"
            "shodan search --fields ip_str,port,org '<query>'"
        ),
        rel_path="dorks.txt",
        abs_path=path,
        lines=lines,
        raw=raw,
        read_via=how,
    ))
    return d


# --------------------------------------------------------------------------- #
# entry construction
# --------------------------------------------------------------------------- #
_KIND_BLURB = {
    "payload-set": (
        "A **payload corpus** — a set of interchangeable payloads for one vulnerability "
        "class, meant to be fed to a fuzzer, not read top to bottom."
    ),
    "dork-list": (
        "A **dork list** — a set of search queries. Each line is run against the search "
        "engine named below; the value is in the set, not in any single query."
    ),
    "checklist": (
        "A **checklist** — an ordered sequence of checks, meaningful in order."
    ),
}


def build_entry(c: Corpus) -> dict:
    """One Corpus -> one canonical KB entry (capped body, sidecar pointer in meta)."""
    sidecar_rel = f"payloads/{c.entry_id}.txt"
    container_path = f"{CONTAINER_PAYLOAD_DIR}/{c.entry_id}.txt"
    sample, truncated = _excerpt(c.lines)
    recipe = c.recipe.format(p=container_path)
    noun = "queries" if c.kind == "dork-list" else "payloads"

    summary = (
        f"{len(c.lines):,} {noun} from PayloadsAllTheThings' `{c.rel_path}`."
        if c.source == "payloadsallthethings"
        else f"{len(c.lines):,} {noun} from `{c.rel_path}`."
    )

    body = [
        _KIND_BLURB.get(c.kind, ""),
        "",
        f"**Corpus:** {len(c.lines):,} {noun} · {len(c.raw):,} bytes  ",
        f"**Source file:** `{c.rel_path}` ({c.source_label})  ",
        f"**Full list on disk:** `data/kb/{sidecar_rel}`  ",
        f"**Inside the sandbox:** `{container_path}` (mounted read-only)",
        "",
        "## Use it",
        "",
        "```bash",
        recipe,
        "```",
        "",
        f"## Sample — first {len(sample.splitlines())} of {len(c.lines):,} {noun}",
        "",
        "```text",
        sample,
        "```",
        "",
    ]
    if truncated:
        body.append(
            f"*Excerpt only. The complete {len(c.lines):,}-line corpus is the sidecar "
            f"file above — this entry exists to make it findable, not to reproduce it.*"
        )

    entry = Entry(
        id=c.entry_id,
        title=c.title,
        category=c.category,
        subcategory=c.subcategory,
        source=c.source,
        tier=3,
        tags=c.tags,
        tools=["ffuf", "wfuzz"] if c.kind == "payload-set" else [],
        summary=summary,
        steps=[{
            "n": 1,
            "text": f"Point a fuzzer at the corpus ({len(c.lines):,} {noun}).",
            "code": [{"lang": "bash", "cmd": recipe}],
        }],
        body_md="\n".join(body).strip() + "\n",
        references=[],
        meta={
            # --- idempotency / provenance -------------------------------- #
            CORPUS_MARK: True,
            "kind": c.kind,
            # Never let consolidate.py fold a corpus into a technique page: a
            # payload set is a corpus, and collapsing it is exactly the §4.4
            # defect this ingester exists to undo.
            "no_merge": True,
            "source_full": c.source_label,
            "source_path": c.rel_path,
            # --- the sidecar --------------------------------------------- #
            "corpus_file": sidecar_rel,
            "corpus_container_path": container_path,
            "corpus_lines": len(c.lines),
            "corpus_bytes": len(c.raw),
            "corpus_sha256": _sha256(c.raw),
            "corpus_truncated_in_body": truncated,
        },
    )
    return entry.model_dump()


# --------------------------------------------------------------------------- #
# oscp_tools -> Scripts Arsenal
# --------------------------------------------------------------------------- #
# Folder -> the arsenal group it belongs in (scripts_index.TYPES keys).
_TOOL_GROUPS: dict[str, str] = {
    "Active Directory": "enumeration",
    "Client Side Attacks": "payloads-delivery",
    "Credentials Extractors": "privesc",
    "Cross-Compiling": "payloads-delivery",
    "GitDumper": "enumeration",
    "Network Utilities": "payloads-delivery",
    "Potatoes": "privesc",
    "Privilege Escalation": "privesc",
}

# Extensions we surface, and the platform each implies.
_TOOL_EXT = {
    ".ps1": ("powershell", "windows"),
    ".exe": ("binary", "windows"),
    ".sh": ("bash", "linux"),
    ".py": ("python", "any"),
    ".c": ("c", "any"),
    ".lnk": ("binary", "windows"),
    ".library-ms": ("xml", "windows"),
}

# Folders with no runnable-script value: wordlists duplicate SecLists (already in
# the image) and dnSpy is an interactive GUI decompiler, not a script.
_TOOL_SKIP_DIRS = {"Wordlists", "dnSpy", ".git"}
_TOOL_SKIP_NAMES = {"LICENSE", "README.md", ".gitattributes", ".gitignore"}

TOOL_PREVIEW_CHARS = 900


def _sniff(raw: bytes) -> tuple[str, str] | None:
    """(lang, platform) for an extension-less file, from its magic bytes."""
    if raw.startswith(b"\x7fELF"):
        return "binary", "linux"
    if raw.startswith(b"MZ"):
        return "binary", "windows"
    if raw.startswith(b"#!"):
        first = raw[:120].decode("utf-8", errors="replace").lower()
        return ("python" if "python" in first else "bash"), "linux"
    return None


def discover_tool_files(root: Path) -> tuple[list[dict], list[dict]]:
    """`oscp_tools` -> Scripts Arsenal rows. Returns (rows, flagged)."""
    rows: list[dict] = []
    flagged: list[dict] = []
    if not root.is_dir():
        return rows, [{"file": str(root), "reason": "oscp_tools source path not found"}]

    for path in all_files(root, ""):
        rel = path.relative_to(root)
        if set(rel.parts) & _TOOL_SKIP_DIRS:
            flagged.append({"file": str(rel), "reason": "skipped directory"})
            continue
        if path.name in _TOOL_SKIP_NAMES:
            continue
        ext = path.suffix.lower()
        if ext and ext not in _TOOL_EXT:
            flagged.append({"file": str(rel), "reason": f"unhandled extension {ext}"})
            continue

        folder = rel.parts[0] if len(rel.parts) > 1 else ""
        group = _TOOL_GROUPS.get(folder, "enumeration")
        raw, how = safe_read_bytes(path, root)
        if raw is None:
            flagged.append({"file": str(rel), "reason": "unreadable on disk and in git"})
            continue

        if ext:
            lang, platform = _TOOL_EXT[ext]
        else:
            # Extension-less files here are the Linux release binaries that matter
            # most for Phase-4 pivoting (chisel_linux, ligolo_agent_linux,
            # ligolo_proxy_linux, nc). Sniff the magic bytes rather than drop them.
            sniffed = _sniff(raw)
            if sniffed is None:
                flagged.append({"file": str(rel), "reason": "no extension, unrecognised magic"})
                continue
            lang, platform = sniffed

        # Text scripts get a short header preview so the arsenal shows what the
        # thing is; binaries never do (a preview of an .exe is noise).
        preview = ""
        if lang != "binary":
            text = raw.decode("utf-8", errors="replace")
            preview = text[:TOOL_PREVIEW_CHARS]

        rows.append({
            # `path.name`, NOT `path.stem` — the stem drops the extension, so two
            # files in one folder that differ only by suffix collided on a single
            # id. Measured 2026-08-04: `nc`/`nc.exe` (linux vs windows) and
            # `SharpHound.ps1`/`SharpHound.exe` shared an id, which made one of
            # each pair unaddressable at /entry/{id} and made React drop one of
            # the pair from the Scripts Arsenal list. The extension is part of
            # the file's identity here — it is what decides `platform`.
            "id": f"toolfile-{_slug(folder)}-{_slug(path.name)}",
            "name": path.name,
            "group": group,
            "folder": folder,
            "lang": lang,
            # D9: Windows-only tooling is KEPT and MARKED, never silently listed
            # as available — it cannot run in the Linux sandbox.
            "platform": platform,
            "runs_here": platform in ("linux", "any"),
            "bytes": len(raw),
            "sha256": _sha256(raw),
            "host_path": str(path),
            "rel_path": str(rel).replace("\\", "/"),
            "preview": preview,
            "source": "oscp_tools",
            "read_via": how,
        })
    return rows, flagged


# --------------------------------------------------------------------------- #
# writing — additive, byte-preserving, idempotent
# --------------------------------------------------------------------------- #
def merge_into_kb(kb_path: Path, new_entries: list[dict]) -> dict:
    """Replace this ingester's own lines; pass every other line through untouched.

    Kept lines are handled as raw bytes and never JSON round-tripped, so no existing
    entry can drift by a key order or an escape. The write is atomic (tmp + replace)
    so a crash mid-write cannot leave a truncated KB — which matters more than usual
    here because `/data/` is gitignored and has no restore path but a rebuild.
    """
    original = kb_path.read_bytes()
    lines = [ln for ln in original.split(b"\n") if ln.strip()]

    kept: list[bytes] = []
    dropped = 0
    mark = CORPUS_MARK.encode()
    for raw in lines:
        if mark in raw:  # cheap pre-filter — only parse candidates
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                kept.append(raw)
                continue
            if (obj.get("meta") or {}).get(CORPUS_MARK):
                dropped += 1
                continue
        kept.append(raw)

    added = [json.dumps(e, ensure_ascii=False).encode("utf-8") for e in new_entries]
    payload = b"\n".join(kept + added) + b"\n"

    tmp = kb_path.with_suffix(".jsonl.tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, kb_path)

    return {
        "kb_lines_before": len(lines),
        "kb_lines_after": len(kept) + len(added),
        "existing_kept": len(kept),
        "previous_corpus_lines_replaced": dropped,
        "corpus_lines_written": len(added),
    }


def write_sidecars(corpora: list[Corpus], out_dir: Path) -> dict:
    """Write each corpus verbatim, and prune sidecars no longer backed by a source."""
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = {f"{c.entry_id}.txt" for c in corpora}
    written = 0
    for c in corpora:
        dest = out_dir / f"{c.entry_id}.txt"
        # Byte-identical rewrite is a no-op — keeps mtimes stable across re-runs.
        if dest.exists() and dest.read_bytes() == c.raw:
            continue
        dest.write_bytes(c.raw)
        written += 1
    pruned = 0
    for stale in out_dir.glob("*.txt"):
        if stale.name not in wanted:
            stale.unlink()
            pruned += 1
    return {"sidecars": len(wanted), "rewritten": written, "pruned": pruned}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kb", default=str(DEFAULT_KB))
    ap.add_argument("--patt-path", default=str(DEFAULT_PATT))
    ap.add_argument("--shodan-path", default=str(DEFAULT_SHODAN))
    ap.add_argument("--oscp-tools-path", default=str(DEFAULT_OSCP_TOOLS))
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would change; write nothing.")
    args = ap.parse_args()

    kb_path = Path(args.kb)
    if not kb_path.is_file():
        sys.exit(f"KB not found: {kb_path}")

    patt = discover_patt(Path(args.patt_path))
    shodan = discover_shodan(Path(args.shodan_path))
    tool_rows, tool_flagged = discover_tool_files(Path(args.oscp_tools_path))

    corpora = patt.corpora + shodan.corpora
    flagged = patt.flagged + shodan.flagged + tool_flagged

    # Duplicate ids would silently overwrite a sidecar — fail loudly instead.
    ids = [c.entry_id for c in corpora]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        sys.exit(f"duplicate entry ids from discovery: {dupes}")

    entries = [build_entry(c) for c in corpora]
    by_kind: dict[str, int] = {}
    for c in corpora:
        by_kind[c.kind] = by_kind.get(c.kind, 0) + 1

    report = {
        "corpora": len(corpora),
        "by_kind": by_kind,
        "corpus_bytes": sum(len(c.raw) for c in corpora),
        "corpus_lines": sum(len(c.lines) for c in corpora),
        "tool_files": len(tool_rows),
        "tool_files_by_platform": {
            p: sum(1 for r in tool_rows if r["platform"] == p)
            for p in sorted({r["platform"] for r in tool_rows})
        },
        # How many files the working copy refused and git had to supply — an
        # environment signal (AV locks / OneDrive dehydration), not a content gap.
        "recovered_from_git": (
            sum(1 for c in corpora if c.read_via == "git")
            + sum(1 for r in tool_rows if r["read_via"] == "git")
        ),
        "flagged": flagged,
    }

    if args.dry_run:
        report["dry_run"] = True
        print(json.dumps(report, indent=2)[:4000])
        return

    # EVERY output lands beside the KB that was passed in. With the default --kb that is
    # data/kb, byte-identical to before; with a copy it is the copy's directory, so a test
    # or a trial run cannot reach production. See the note on PAYLOAD_DIRNAME.
    out_dir = kb_path.parent
    report.update(write_sidecars(corpora, out_dir / PAYLOAD_DIRNAME))
    report.update(merge_into_kb(kb_path, entries))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / TOOLFILES_NAME).write_text(
        json.dumps({"total": len(tool_rows), "files": tool_rows}, indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / REPORT_NAME).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({k: v for k, v in report.items() if k != "flagged"}, indent=2))
    print(f"flagged: {len(flagged)} (see {REPORT_OUT.name})")


if __name__ == "__main__":
    main()
