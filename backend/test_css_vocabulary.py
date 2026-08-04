"""EVERY `hp-*` CLASS A SCREEN USES MUST EXIST IN globals.css.

*** tsc, `next build` and eslint CANNOT SEE WHETHER A CSS CLASS EXISTS. *** A component can
name a class nobody ever wrote, and all three tools pass. This has now cost three builds:

  * `:proxy` shipped ENTIRELY INVISIBLE for two builds — six of its eight classes did not
    exist, and a bare `.hp-card` starts at `opacity: 0`.
  * `.hp-tn-start` did not exist while NINE buttons across `:exposure`, `:oob` and `:windows`
    used it. The PRIMARY action on each of those screens therefore rendered plainer than the
    destructive button beside it — the visual hierarchy was exactly backwards, and the only
    reason anyone found out was a human looking at the screen.
  * `.hp-tn-input` does not exist either; it survives only because `.hp-tn-form input`
    happens to style the same elements by tag. A silent near-miss.

So this is the check the type-checker cannot do. It is not a substitute for looking at the
screen — a class can exist and still be wrong — but "the class exists at all" is mechanical,
and mechanical things belong in the suite rather than in a reviewer's memory.

SCOPE: only `hp-`-prefixed classes, which are this project's own vocabulary and all live in
`frontend/src/app/globals.css`. Tailwind utilities (`mt-3`, `text-slate-400`) are generated
and deliberately not checked. Only `className` attributes are scanned — the first version
read every quoted string and reported `hp-set-model`/`hp-set-key`, which are element **ids**
paired with `htmlFor`. A checker whose failures are partly bogus gets an allow-list full of
bogus entries, and then it is not a checker any more.

TWO LISTS, KEPT APART ON PURPOSE. `_ALLOWED_ABSENT` means *checked, and fine* — each entry
carries the reason (a modifier on a defined base; an element selector doing the work).
`_PRE_EXISTING_PHANTOMS` means *known, and unexamined*: eleven bare classes this check found
the first time it ran, in screens nobody has since looked at with them in mind. Freezing
them keeps the check useful today without pretending they are harmless, and the baseline is
asserted to only ever SHRINK — entries that get defined, or fall out of use, must be
removed. Collapsing the two lists into one would erase the distinction between "fine" and
"unexamined", which is the failure mode that turns a guard like this into decoration.

Hermetic (reads files). Run:  python test_css_vocabulary.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = REPO_ROOT / "frontend" / "src"
CSS = FRONTEND / "app" / "globals.css"

#: Classes that are legitimately absent from globals.css. Each needs a REASON — an
#: unexplained entry here is how this check gets hollowed out one exception at a time.
_ALLOWED_ABSENT: dict[str, str] = {
    # styled by `.hp-tn-form input` / `.hp-tn-form select` on the element, not the class.
    # Kept as a readable marker at the call sites; harmless, but genuinely undefined.
    "hp-tn-input": "styled by the `.hp-tn-form input` element selector, not by this class",
    # MODIFIERS ON A DEFINED BASE. Each is the second class on an element whose first class
    # exists and does the styling, so the element renders correctly and the modifier is a
    # hook nobody ever wrote a rule for. Harmless, and NOT the same thing as a bare phantom.
    "hp-eng-live": "modifier on `hp-eng`, which is defined and does the styling",
    "hp-eng-phases": "modifier on `hp-ap-phases`, which is defined and does the styling",
    "hp-rp-respcode-wrap": "modifier on `hp-code`, which is defined and does the styling",
    "hp-tn-olcode": "modifier on `hp-code`, which is defined and does the styling",
}

#: PRE-EXISTING PHANTOMS — the debt this check found the first time it ran, frozen.
#:
#: These are BARE classes: the only class on their element, with no rule anywhere. They are
#: not this build's doing and they are NOT declared harmless — nobody has looked at these
#: screens with them in mind. Freezing the list rather than allow-listing them keeps the
#: distinction honest: `_ALLOWED_ABSENT` above means "checked, fine"; this means "known,
#: unexamined". The same shape as the accepted eslint baseline in frontend/AGENTS.md.
#:
#: The check still does its job — anything NOT in this list fails — and the list may only
#: ever SHRINK (asserted below), so the debt can be paid down but never quietly grown.
_PRE_EXISTING_PHANTOMS: frozenset[str] = frozenset({
    "hp-ap-goal",             # AttackPathScreen
    "hp-asst-empty",          # EngagementAssistant
    "hp-asst-head-titles",    # EngagementAssistant
    "hp-cm-phase",            # CockpitAttackMap
    "hp-listing",             # CategoryScreen
    "hp-rp-bodywrap",         # RepeaterScreen
    "hp-rp-headers",          # RepeaterScreen
    "hp-rp-respbody",         # RepeaterScreen
    "hp-rp-rhrow",            # RepeaterScreen
    "hp-xp",                  # ExploitsScreen
    "hp-xp-results",          # ExploitsScreen
})


#: A `className` attribute, in either form: `className="…"` or `className={…}`. The braced
#: form allows ONE level of nesting so a template literal's `${…}` does not end the match.
_CLASSNAME_RE = re.compile(
    r'className\s*=\s*(?:"([^"]*)"|\{((?:[^{}]|\{[^{}]*\})*)\})', re.S
)


def _class_names_in(text: str) -> set[str]:
    """Every `hp-*` CSS class named in a `className` attribute.

    SCOPED TO className ON PURPOSE. The first version of this scanned every quoted string in
    the file, and immediately produced two false positives: `hp-set-model` and `hp-set-key`
    are element **ids** in LLMSettingsModal.tsx, paired with `htmlFor` — they are not CSS
    classes and were never meant to be in globals.css. A checker whose failures are partly
    bogus is a checker whose allow-list becomes a dumping ground, and then it stops working
    at all. The predicate has to be "is a class", not "looks like one".
    """
    found: set[str] = set()
    for quoted, braced in _CLASSNAME_RE.findall(text):
        # In the braced form the value is an expression — a template literal, a ternary, a
        # clsx() call. Every class it can produce is in one of its string literals.
        chunks = [quoted] if quoted else re.findall(
            r'"([^"]*)"|\'([^\']*)\'|`([^`]*)`', braced
        )
        for chunk in chunks:
            parts = [chunk] if isinstance(chunk, str) else list(chunk)
            for part in parts:
                for token in part.split():
                    if re.fullmatch(r"hp-[a-z0-9-]+", token):
                        found.add(token)
    return found


def _defined_classes() -> set[str]:
    css = CSS.read_text(encoding="utf-8")
    # Strip comments so a class named only inside an explanatory note does not count as
    # defined — that would let a comment "define" a phantom.
    css = re.sub(r"/\*.*?\*/", " ", css, flags=re.S)
    return set(re.findall(r"\.(hp-[a-z0-9-]+)", css))


def test_every_hp_class_used_by_a_screen_is_defined() -> None:
    defined = _defined_classes()
    assert len(defined) > 100, (
        f"only {len(defined)} hp-* classes parsed out of globals.css — the parser is broken, "
        "and a broken parser here would pass everything"
    )

    missing: dict[str, list[str]] = {}
    files = sorted(FRONTEND.rglob("*.tsx"))
    assert files, "no .tsx files found — this check would pass vacuously"
    known = set(_ALLOWED_ABSENT) | _PRE_EXISTING_PHANTOMS
    for path in files:
        for cls in _class_names_in(path.read_text(encoding="utf-8")):
            if cls in defined or cls in known:
                continue
            missing.setdefault(cls, []).append(str(path.relative_to(REPO_ROOT)))

    if missing:
        lines = [
            f"  .{cls}  — used in {', '.join(sorted(set(f))[:3])}"
            for cls, f in sorted(missing.items())
        ]
        raise AssertionError(
            "these hp-* classes are used by a component and DO NOT EXIST in globals.css.\n"
            "tsc, next build and eslint all pass on them; the element renders unstyled.\n"
            + "\n".join(lines)
            + "\n\nDefine each in globals.css, or — if it is genuinely fine — add it to "
            "_ALLOWED_ABSENT with the reason why."
        )
    print(
        f"  no NEW hp-* phantom classes across {len(files)} components "
        f"({len(defined)} classes defined, {len(_PRE_EXISTING_PHANTOMS)} pre-existing "
        f"phantoms frozen): PASS"
    )


def test_the_check_can_fail() -> None:
    """POSITIVE CONTROL. A checker of absences that cannot detect one is worthless."""
    defined = _defined_classes()
    planted = _class_names_in('<div className="hp-tn-card hp-hackpit-planted-phantom" />')
    assert "hp-hackpit-planted-phantom" in planted, planted
    assert "hp-hackpit-planted-phantom" not in defined, "the planted class somehow exists"
    assert "hp-tn-card" in defined, "the extractor found a real class the CSS does not define"

    # ...and a class named ONLY in a CSS comment must not count as defined, or an
    # explanatory note could silently satisfy this check.
    commented = re.sub(r"/\*.*?\*/", " ", "/* .hp-only-in-a-comment {} */", flags=re.S)
    assert "hp-only-in-a-comment" not in set(re.findall(r"\.(hp-[a-z0-9-]+)", commented))
    print("  positive control: a phantom class IS detected, a commented one is not: PASS")


def test_the_allowlist_is_not_a_dumping_ground() -> None:
    """Every documented exception must still be a real absence — an entry that has since been
    defined should be REMOVED, not left to hide a future regression."""
    defined = _defined_classes()
    stale = sorted(c for c in _ALLOWED_ABSENT if c in defined)
    assert not stale, (
        f"these classes are allow-listed as absent but now EXIST: {stale}. Remove them from "
        "_ALLOWED_ABSENT so the check covers them again."
    )
    for cls, reason in _ALLOWED_ABSENT.items():
        assert len(reason) > 20, f"{cls} is allow-listed without a real reason"
    print(f"  all {len(_ALLOWED_ABSENT)} allow-listed absences are still real + reasoned: PASS")


def test_the_frozen_baseline_only_ever_shrinks() -> None:
    """The debt list may be paid down. It may not be grown, and it may not go stale.

    A frozen baseline is only worth having if it is enforced in BOTH directions: an entry
    that has since been defined must be removed (or it silently covers a future regression),
    and an entry for a class no component uses any more is dead weight that makes the list
    look bigger than the problem.
    """
    defined = _defined_classes()
    now_defined = sorted(c for c in _PRE_EXISTING_PHANTOMS if c in defined)
    assert not now_defined, (
        f"these are in the frozen phantom baseline but now EXIST in globals.css: "
        f"{now_defined}. Remove them from _PRE_EXISTING_PHANTOMS — the debt was paid, and "
        "leaving the entry there would hide the next regression on the same class."
    )

    used: set[str] = set()
    for path in FRONTEND.rglob("*.tsx"):
        used |= _class_names_in(path.read_text(encoding="utf-8"))
    unused = sorted(c for c in _PRE_EXISTING_PHANTOMS if c not in used)
    assert not unused, (
        f"these are in the frozen phantom baseline but no component uses them any more: "
        f"{unused}. Remove them — the baseline should describe the real debt, not history."
    )
    # ...and the two lists must not overlap: a class is either "checked, fine" or "known,
    # unexamined", and one meaning per entry is the whole point of keeping them apart.
    overlap = sorted(set(_ALLOWED_ABSENT) & _PRE_EXISTING_PHANTOMS)
    assert not overlap, f"these appear in BOTH lists, which means neither: {overlap}"
    print(
        f"  the {len(_PRE_EXISTING_PHANTOMS)}-class phantom baseline is current, "
        "non-overlapping and unpaid: PASS"
    )


if __name__ == "__main__":
    if not CSS.is_file():
        print(f"  (skipped — no globals.css at {CSS})")
        sys.exit(0)
    test_every_hp_class_used_by_a_screen_is_defined()
    test_the_check_can_fail()
    test_the_allowlist_is_not_a_dumping_ground()
    test_the_frozen_baseline_only_ever_shrinks()
    print("ALL CSS vocabulary checks pass")
