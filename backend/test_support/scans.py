"""ONE source-tree scanner for every human-only / decoupling lock in the safety suites.

WHY THIS MODULE EXISTS. Several suites each carried their own copy of a source scan, and the
copies were narrower than their own docstrings claimed. The `:kali` lock — the entire reason
the one deliberately-unbounded arbitrary-shell surface is considered safe — globbed
``backend/*.py`` plus ``backend/cockpit/*.py``: 30 of 69 modules. A planted
``from cockpit.kali import run_kali`` in ``adgraph/orchestrator.py`` shipped green. The same
glob was copied into the tunnels, repeater, terminal and WinRM locks; the cockpit->arsenal lock
was a hardcoded list of five filenames out of twenty-two.

Three defects, all of which this module fixes structurally rather than by asking each suite to
remember:

1. NARROW FILE SELECTION. :func:`source_files` is an ``rglob`` over the whole backend. There is
   no per-suite glob left to get wrong.
2. BASENAME ALLOW-LISTS. ``allowed = {"router.py"}`` matched with ``f.name in allowed`` exempted
   ``adgraph/router.py``, ``detection/router.py``, ``arsenal/router.py`` and every other
   ``router.py`` in the tree by accident. Allow-lists here are keyed on REPO-RELATIVE POSIX
   PATHS and nothing else.
3. COUNTING FILES OPENED, NOT FILES CHECKED. A control that asserted ``scanned > 40`` counted
   files opened BEFORE the filter that decided whether to read them; 5 were really inspected.
   :class:`ScanResult` reports ``checked`` and ``skipped`` separately, and ``checked`` means the
   content was actually matched against the patterns.

See ``backend/AGENTS.md`` for the convention these enforce.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

BACKEND = Path(__file__).resolve().parent.parent

# Never source. `.venv` alone is ~thousands of files and none of it is ours.
_SKIP_DIRS = frozenset({".venv", "__pycache__", "node_modules", ".pytest_cache", ".git"})


def source_files(root: Path | None = None) -> list[Path]:
    """Every backend ``.py`` file, minus the venv and caches. The WHOLE tree, always."""
    base = root or BACKEND
    return sorted(
        p for p in base.rglob("*.py")
        if not (set(p.relative_to(base).parts) & _SKIP_DIRS)
    )


def rel(path: Path, root: Path | None = None) -> str:
    """The repo-relative POSIX path — the ONLY key an allow-list may use."""
    return path.relative_to(root or BACKEND).as_posix()


# --------------------------------------------------------------------------- #
# prose stripping
# --------------------------------------------------------------------------- #
def code_without_prose(text: str) -> str:
    """Source with COMMENTS and DOCSTRINGS blanked in place — other string literals KEPT.

    Blanking prose is necessary: a scan over raw text reads a docstring sentence as if it were
    code, and a module that merely EXPLAINS a rule trips the rule. (That is not hypothetical —
    documenting this fix tripped the WinRM lock.)

    Keeping ordinary string literals is equally necessary, and is the half that is easy to get
    wrong. A scanner that blanked every string would be blind to
    ``importlib.import_module("cockpit.kali")`` — the exact indirection these locks exist to
    catch. So docstrings are located structurally (the first statement of a module, class or
    function) rather than by blanking the STRING token class wholesale.

    Spans are blanked IN PLACE, preserving every other byte and all spacing, so offsets and
    lookbehind-style patterns keep working.
    """
    lines = text.splitlines(keepends=True)

    def blank(start: tuple[int, int], end: tuple[int, int]) -> None:
        (srow, scol), (erow, ecol) = start, end
        for row in range(srow, min(erow, len(lines)) + 1):
            if row - 1 >= len(lines):
                return
            line = lines[row - 1]
            begin = scol if row == srow else 0
            finish = ecol if row == erow else len(line)
            finish = min(finish, len(line))
            if finish > begin:
                lines[row - 1] = line[:begin] + " " * (finish - begin) + line[finish:]

    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                blank(tok.start, tok.end)
    except (tokenize.TokenError, IndentationError, SyntaxError):  # pragma: no cover
        return text

    try:
        tree = ast.parse(text)
    except SyntaxError:  # pragma: no cover
        return "".join(lines)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            blank((first.lineno, first.col_offset),
                  (first.end_lineno or first.lineno, first.end_col_offset or 0))
    return "".join(lines)


# --------------------------------------------------------------------------- #
# AST indirection
# --------------------------------------------------------------------------- #
def _fold(node: ast.AST) -> str | None:
    """A string this expression provably evaluates to, or None.

    Handles the two shapes a substring scan cannot see: ``"cockpit." + "kali"`` and
    ``f"cockpit.{name}"`` with constant parts. Deliberately conservative — it folds what it
    can prove and reports nothing otherwise.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left), _fold(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("\x00")  # an unknown slot; still lets a literal prefix match
        return "".join(parts)
    return None


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def ast_reference_hits(text: str, targets: Sequence[str]) -> list[str]:
    """Names in ``targets`` reached by IMPORT or by INDIRECTION anywhere in this module.

    A four-literal-substring predicate is defeated by things the audit actually demonstrated:
    an aliased import, an import opened inside a function body, and
    ``getattr(importlib.import_module("cockpit." + "kali"), "run_" + "kali")``. ``ast.walk``
    sees in-function imports for free; the rest is constant folding.

    Returns human-readable hits (``why`` strings), empty when clean.
    """
    if not targets:
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:  # pragma: no cover
        return []
    wanted = set(targets)
    hits: list[str] = []

    def note(kind: str, name: str, lineno: int) -> None:
        hits.append(f"{kind} {name!r} (line {lineno})")

    def matches(name: str) -> str | None:
        for t in wanted:
            if name == t or name.endswith("." + t) or name.startswith(t + "."):
                return t
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if matches(a.name):
                    note("import", a.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                full = f"{mod}.{a.name}" if mod else a.name
                if matches(full) or matches(a.name) or matches(mod):
                    note("from-import", full, node.lineno)
        elif isinstance(node, ast.Call):
            callee = _dotted(node.func)
            if callee.split(".")[-1] not in ("import_module", "__import__", "getattr"):
                continue
            for arg in node.args:
                folded = _fold(arg)
                if folded and any(t in folded for t in wanted):
                    note(f"{callee}(...)", folded, node.lineno)
    return hits


# --------------------------------------------------------------------------- #
# the scan
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    """What a scan actually did — separated so a count assertion can mean something."""

    checked: list[str] = field(default_factory=list)     # content really matched
    skipped: list[str] = field(default_factory=list)     # allow-listed / test infra
    offenders: list[str] = field(default_factory=list)   # violations, by repo-relative path
    controls: dict[str, list[str]] = field(default_factory=dict)  # allow-listed file -> hits

    def __len__(self) -> int:
        return len(self.checked)


def scan_source_tree(
    *,
    patterns: Sequence[str],
    allowed: Iterable[str] = (),
    ast_targets: Sequence[str] = (),
    root: Path | None = None,
    skip_tests: bool = True,
    strip_prose: bool = True,
) -> ScanResult:
    """Scan EVERY backend module for ``patterns`` (regex) and ``ast_targets`` (indirection).

    ``allowed`` is a set of REPO-RELATIVE POSIX PATHS — ``"cockpit/router.py"``, never
    ``"router.py"``. Allow-listed files are not offenders, but they ARE recorded in
    ``controls`` with whatever they matched, so a caller can assert the patterns still fire
    somewhere. A pattern set that has rotted into matching nothing is a scan that passes
    vacuously, which is the failure this whole module exists to make impossible.
    """
    base = root or BACKEND
    allow = set(allowed)
    compiled = [(p, re.compile(p)) for p in patterns]
    out = ScanResult()

    for path in source_files(base):
        name = rel(path, base)
        raw = path.read_text(encoding="utf-8", errors="ignore")
        text = code_without_prose(raw) if strip_prose else raw
        hits = [p for p, rx in compiled if rx.search(text)]
        hits += ast_reference_hits(raw, ast_targets)

        if name in allow:
            out.controls[name] = hits
            out.skipped.append(name)
            continue
        if skip_tests and (path.name.startswith("test_") or path.parts[-2] == "test_support"):
            # Test modules and this shared machinery are not the runtime agent path, and several
            # legitimately name a banned symbol inside an assertion that a module must NOT use it.
            out.skipped.append(name)
            continue

        out.checked.append(name)
        if hits:
            out.offenders.append(f"{name} ({', '.join(hits)})")
    return out


def assert_clean(
    result: ScanResult,
    *,
    what: str,
    must_have_scanned: Iterable[str] = (),
    min_checked: int = 40,
    require_controls: bool | Iterable[str] = True,
) -> None:
    """Assert a scan found nothing AND was capable of finding something.

    Four assertions, because "no offenders" alone is what a vacuous guard also reports:
      * no offenders;
      * the modules that matter were REALLY checked (named, so a rename fails here);
      * enough modules were checked to be a sweep, counted on ``checked`` not on files opened;
      * every allow-listed file still MATCHES, so a rename cannot empty the patterns silently.
    """
    assert not result.offenders, (
        f"{what} — these modules can reach it: {result.offenders}"
    )
    missing = sorted(set(must_have_scanned) - set(result.checked))
    assert not missing, (
        f"{what}: the scan never reached {missing} — coverage was lost, so a clean result "
        "here proves nothing about them"
    )
    assert len(result.checked) >= min_checked, (
        f"{what}: only {len(result.checked)} modules were content-checked (min {min_checked}) "
        "— the sweep has narrowed"
    )
    if require_controls:
        # `True` means every allow-listed file must still match. An explicit iterable is for
        # the case where an allow-listed file legitimately CANNOT match — a package's own
        # module does not import itself — and demanding it would force a permanently-failing
        # control. Naming the ones that must match keeps the guarantee where it is real.
        wanted = (set(result.controls) if require_controls is True
                  else set(require_controls))
        empty = sorted(n for n in wanted if not result.controls.get(n))
        assert not empty, (
            f"{what}: allow-listed {empty} no longer match any pattern — the scan would now "
            "pass vacuously. Follow the rename."
        )


PLANTED_VIOLATION = "adgraph/orchestrator.py"


def assert_catches_a_planted_violation(
    *,
    plant: str,
    patterns: Sequence[str],
    allowed: Iterable[str] = (),
    ast_targets: Sequence[str] = (),
    where: str = PLANTED_VIOLATION,
) -> None:
    """THE POSITIVE CONTROL, made cheap enough that every lock can carry one.

    Mirrors the real backend into a temp tree, writes ``plant`` into ``where``, and asserts the
    SAME scanner configuration reports it. A guard test with no demonstration that it can fail
    is not evidence — and every critical in the gate audit was a guard that could not fail.

    ``where`` defaults to ``adgraph/orchestrator.py`` on purpose: it is a literal orchestrator
    module that the old ``backend/*.py + cockpit/*.py`` glob never opened.
    """
    import tempfile

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tree = Path(tmp)
        target = tree / where
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(plant + "\n", encoding="utf-8")
        # a decoy in a directory the OLD globs did cover, so a pass cannot come from the
        # scanner having quietly fallen back to the narrow selection
        (tree / "cockpit").mkdir(parents=True, exist_ok=True)
        (tree / "cockpit" / "unrelated.py").write_text("x = 1\n", encoding="utf-8")

        planted = scan_source_tree(
            patterns=patterns, allowed=allowed, ast_targets=ast_targets, root=tree,
        )
        assert planted.offenders, (
            f"the scanner did NOT catch a planted {plant!r} in {where} — this lock cannot fail, "
            "so its green result means nothing"
        )
        assert any(where in o for o in planted.offenders), (
            f"the violation was found but not attributed to {where}: {planted.offenders}"
        )

        target.write_text("x = 1\n", encoding="utf-8")
        clean = scan_source_tree(
            patterns=patterns, allowed=allowed, ast_targets=ast_targets, root=tree,
        )
        assert not clean.offenders, (
            f"the scanner reports a violation in a CLEAN tree: {clean.offenders} — it would "
            "fail on everything, which is just as useless as failing on nothing"
        )
