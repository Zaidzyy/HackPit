"""Find the SILENT EMPTY: an error path that returns nothing and reads as "nothing is there".

*** WHY THIS EXISTS. *** Three defects in build #17 were the same shape:

    the API key was lost      -> `history()` returned []   -> "no traffic was captured"
    the bytes would not decode-> `history()` returned []   -> "no traffic was captured"
    the history window was wrong -> session_health saw the oldest 200 -> a confident `ok`

None of them raised. None of them logged. Each produced a confident, successful-looking ZERO
that a human had no reason to doubt, and one of them had been failing for as long as the code
existed. That is the worst failure shape this project recognises, and build #18 item 8 is a
sweep for the rest of them.

*** AST, NOT SUBSTRING. *** This repo has been caught by a grep reading a docstring as code —
the module docstrings here are FULL of the literal text `return []` describing the very bug
being hunted, so a regex would report this file as its own worst offender. Everything below
walks a parsed tree.

*** IT REPORTS. IT DOES NOT JUDGE. *** Not every empty return is a defect. A parser that returns
[] for "this input legitimately contains nothing" is correct. What makes one a defect is that
THE CALLER CANNOT TELL "empty" FROM "failed" — and that is a question about the caller, which a
scanner cannot answer. So this ranks by how likely that is and a human reads the list.

Run:  python tools/silent_empty_scan.py [--json]
Exit code is always 0: this is a reporting tool, not a gate. Making it fail a build would turn
every legitimate empty return into work, which is how a control stops being read.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

#: The packages build #18 item 8 names. Relative to backend/.
PACKAGES = ("cockpit", "state", "arsenal", "reasoning")

#: Values that read as "nothing is there" when they come out of an error path.
_EMPTY_KINDS = {
    "list": "[]",
    "dict": "{}",
    "str": '""',
    "int0": "0",
    "none": "None",
    "false": "False",
}


def _empty_kind(node: ast.AST | None) -> str | None:
    """Which flavour of empty this expression is, or None if it is not one."""
    if node is None:
        return "none"
    if isinstance(node, ast.List) and not node.elts:
        return "list"
    if isinstance(node, ast.Dict) and not node.keys:
        return "dict"
    if isinstance(node, ast.Tuple) and not node.elts:
        return "list"
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None:
            return "none"
        if value == "" and isinstance(value, str):
            return "str"
        if value is False:
            return "false"
        if isinstance(value, int) and not isinstance(value, bool) and value == 0:
            return "int0"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ("list", "dict", "set", "tuple", "frozenset") and not node.args:
            return {"list": "list", "tuple": "list"}.get(node.func.id, "dict")
    return None


class _Finder(ast.NodeVisitor):
    """Collect every empty return that sits under an exception handler or a falsy guard."""

    def __init__(self, path: Path, source: str) -> None:
        self.path = path
        self.lines = source.splitlines()
        self.hits: list[dict] = []
        self._fn: list[str] = []

    # -- context tracking ---------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._fn.append(node.name)
        self._scan_function(node)
        self.generic_visit(node)
        self._fn.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # -- the actual work ----------------------------------------------------
    def _scan_function(self, fn: ast.AST) -> None:
        for node in ast.walk(fn):
            if isinstance(node, ast.ExceptHandler):
                self._collect(node, "except", self._handler_label(node))
            elif isinstance(node, ast.If):
                label = self._guard_label(node)
                if label:
                    self._collect_body(node.body, "guard", label)

    @staticmethod
    def _handler_label(node: ast.ExceptHandler) -> str:
        if node.type is None:
            return "except:"
        try:
            return "except " + ast.unparse(node.type)
        except Exception:  # noqa: BLE001 - a label is cosmetic
            return "except <?>"

    @staticmethod
    def _guard_label(node: ast.If) -> str:
        """A guard whose whole test is 'this thing is falsy/absent'. "" if it is ordinary logic.

        Deliberately narrow. `if not raw: return []` is the shape that hides a failed read;
        `if count > 5: return []` is ordinary control flow and reporting it would bury the
        signal under the noise, which is how a list stops being read.
        """
        test = node.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            try:
                return "if not " + ast.unparse(test.operand)
            except Exception:  # noqa: BLE001
                return "if not <?>"
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            if isinstance(op, ast.Is) and _empty_kind(test.comparators[0]) == "none":
                try:
                    return "if " + ast.unparse(test)
                except Exception:  # noqa: BLE001
                    return "if <?> is None"
        return ""

    def _collect(self, node: ast.AST, kind: str, label: str) -> None:
        self._collect_body(getattr(node, "body", []), kind, label)

    def _collect_body(self, body: list[ast.stmt], kind: str, label: str) -> None:
        for stmt in body:
            for inner in ast.walk(stmt):
                if not isinstance(inner, ast.Return):
                    continue
                empty = _empty_kind(inner.value)
                if empty is None:
                    continue
                self.hits.append({
                    "file": str(self.path).replace("\\", "/"),
                    "line": inner.lineno,
                    "function": ".".join(self._fn) or "<module>",
                    "path_kind": kind,
                    "trigger": label,
                    "returns": _EMPTY_KINDS[empty],
                    "source": self.lines[inner.lineno - 1].strip()
                    if inner.lineno <= len(self.lines) else "",
                })


def _rank(hit: dict) -> int:
    """How likely the caller cannot tell empty from failed. Higher is worse.

    The ranking is a heuristic and says so. What earns points:
      +3  a bare `except` or one catching Exception — it swallows anything, including bugs
      +2  the function name says it READS something (a caller expects data, not a verdict)
      +2  it returns a COLLECTION — the caller almost certainly iterates it and finds nothing
      +1  the trigger is a falsy guard on a value that came from outside the process
    A `return None` from an `if x is None` guard scores lowest, because None already means
    "no answer" to most callers, which is exactly the distinction that goes missing with [].
    """
    score = 0
    trigger = hit["trigger"]
    if trigger in ("except:", "except Exception", "except BaseException"):
        score += 3
    name = hit["function"].lower()
    if any(w in name for w in ("read", "load", "list", "get", "fetch", "history", "observe",
                               "parse", "scan", "status", "count", "alerts", "resolve")):
        score += 2
    if hit["returns"] in ("[]", "{}"):
        score += 2
    if hit["path_kind"] == "guard" and hit["returns"] in ("[]", "{}", '""', "0"):
        score += 1
    return score


def scan(root: Path) -> list[dict]:
    hits: list[dict] = []
    for package in PACKAGES:
        base = root / package
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            finder = _Finder(path.relative_to(root), source)
            finder.visit(ast.parse(source))
            hits.extend(finder.hits)
    for hit in hits:
        hit["rank"] = _rank(hit)
    hits.sort(key=lambda h: (-h["rank"], h["file"], h["line"]))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--min-rank", type=int, default=0)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    hits = [h for h in scan(root) if h["rank"] >= args.min_rank]

    if args.json:
        print(json.dumps(hits, indent=2))
        return 0

    # ASCII only. The console this project is driven from is cp1252 and an arrow or a section
    # sign here raises UnicodeEncodeError — a trap already paid for twice in this repo.
    print(f"SILENT-EMPTY SWEEP: {len(hits)} empty returns on an error or falsy-guard path")
    print("(a report, not a verdict: an empty return is a DEFECT only when the CALLER cannot")
    print(" tell 'empty' from 'failed'. Ranked by how likely that is.)")
    print()
    current = ""
    for hit in hits:
        if hit["file"] != current:
            current = hit["file"]
            print(f"--- {current}")
        print(f"  rank {hit['rank']}  L{hit['line']:<5} {hit['function']}()"
              f"  [{hit['trigger']}] -> {hit['returns']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
