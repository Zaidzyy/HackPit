"""Build #10 — THE PUBLISHED-PORT INVARIANT.

Build #9's live-fire task 4 could not complete because the engage sandbox publishes NO ports:
the DC has no route to a Docker bridge, so a beacon had nowhere to call back to. The honest
answer recorded then was "publishing a port changes the sandbox's network posture, so the
compose change was not made".

Build #10 makes that change — and this file is the fence around it. The rule is not "no
exposure ever"; it is:

  1. THE DEFAULT POSTURE PUBLISHES NOTHING. `docker compose -f docker/docker-compose.yml up`
     must expose zero ports on the host. Someone who brings the stack up the documented way
     gets exactly what they got before build #10. Exposure is never the default.

  2. EXPOSURE IS OPT-IN AND LIVES IN ITS OWN FILE. It is reachable only by explicitly adding
     a second `-f docker/proof/c2-lab.yml`. A reviewer can see the whole exposure surface by
     reading one small file.

  3. EVERY PUBLISHED PORT IS BOUND TO ONE HOST IP. `"53:53/udp"` and `"0.0.0.0:53:53/udp"`
     bind EVERY interface on the machine — including whatever Wi-Fi the laptop is on. The
     callback only ever needs the VMnet8 host address the lab DC can see, so the binding must
     name it. This is the check that keeps "my DC can reach the listener" from silently
     meaning "so can the coffee-shop network".

WHY A TEXT SCAN AND NOT A YAML PARSE: the hermetic suite must run with no third-party deps
(the same property that keeps pywinrm out of it). Compose port entries are a simple list of
scalars, so a line scan reads them exactly, and a malformed file fails loudly rather than
being silently normalised by a parser.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE = REPO / "docker" / "docker-compose.yml"
EXPOSURE_OVERRIDE = REPO / "docker" / "proof" / "c2-lab.yml"

# A published-port entry that names a host IP: "<ip>:<hostport>:<containerport>[/proto]".
# The IP must be a literal dotted quad — a name would resolve at `up` time to who-knows-what.
_IP_BOUND = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<host>\d+):(?P<cont>\d+)(?:/(?P<proto>tcp|udp))?$")

# The bindings that mean "every interface on this machine".
_WILDCARD_IPS = {"0.0.0.0", "::", "*"}


def _strip_comment(line: str) -> str:
    """Compose allows trailing `# ...`. Only strip it outside quotes."""
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def published_ports(path: Path) -> list[tuple[int, str]]:
    """Every entry under a `ports:` key, as (line_number, value).

    Handles the two forms compose accepts for a scalar list:
        ports:
          - "1.2.3.4:80:80"
        ports: ["1.2.3.4:80:80"]
    """
    if not path.exists():
        return []
    found: list[tuple[int, str]] = []
    in_ports = False
    ports_indent = -1
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if in_ports:
            # A list item deeper than the `ports:` key belongs to it.
            if stripped.startswith("-") and indent > ports_indent:
                found.append((lineno, stripped.lstrip("-").strip().strip("\"'")))
                continue
            # Anything at or above the key's indent ends the block.
            if indent <= ports_indent:
                in_ports = False

        m = re.match(r"^ports:\s*(.*)$", stripped)
        if m and not stripped.startswith("-"):
            inline = m.group(1).strip()
            if inline.startswith("["):
                for item in inline.strip("[]").split(","):
                    item = item.strip().strip("\"'")
                    if item:
                        found.append((lineno, item))
            else:
                in_ports = True
                ports_indent = indent
    return found


def test_default_compose_publishes_nothing() -> None:
    """Invariant 1. The documented bring-up exposes zero ports."""
    assert DEFAULT_COMPOSE.exists(), f"missing {DEFAULT_COMPOSE}"
    offenders = published_ports(DEFAULT_COMPOSE)
    assert not offenders, (
        "docker/docker-compose.yml publishes ports — the DEFAULT posture must expose nothing. "
        f"Move them into {EXPOSURE_OVERRIDE.name}. Offenders: {offenders}"
    )
    print("  default compose publishes NO ports (exposure is never the default): PASS")


def test_exposure_override_is_ip_bound() -> None:
    """Invariant 3. If the opt-in override exists, every port it publishes names a host IP."""
    if not EXPOSURE_OVERRIDE.exists():
        print("  exposure override absent -- nothing to bind-check (vacuously safe): PASS")
        return

    entries = published_ports(EXPOSURE_OVERRIDE)
    assert entries, (
        f"{EXPOSURE_OVERRIDE.name} exists but publishes nothing — either it is dead weight or "
        "the scan below is not seeing its ports. Both are bugs."
    )
    for lineno, value in entries:
        m = _IP_BOUND.match(value)
        assert m, (
            f"{EXPOSURE_OVERRIDE.name}:{lineno} publishes {value!r}, which does NOT name a host "
            "IP. A bare '<host>:<container>' binds EVERY interface on the machine. Write it as "
            "'<vmnet8-ip>:<host>:<container>[/proto]'."
        )
        ip = m.group("ip")
        assert ip not in _WILDCARD_IPS, (
            f"{EXPOSURE_OVERRIDE.name}:{lineno} binds {ip}, which is every interface on the "
            "machine. Bind the single host address the lab DC can reach."
        )
        assert not ip.startswith("0."), (
            f"{EXPOSURE_OVERRIDE.name}:{lineno} binds {ip!r}, which is not a real host address."
        )
    shown = ", ".join(v for _, v in entries)
    print(f"  every published port names one host IP ({len(entries)}: {shown}): PASS")


def test_override_is_not_wired_into_the_default_path() -> None:
    """Invariant 2. Nothing in the repo brings the override up implicitly.

    A helper script that quietly appends `-f docker/proof/c2-lab.yml` to the normal bring-up
    would defeat invariant 1 without touching docker-compose.yml. The exposure has to be typed
    on purpose, every time.
    """
    if not EXPOSURE_OVERRIDE.exists():
        print("  exposure override absent -- nothing could reference it: PASS")
        return

    needle = "c2-lab.yml"
    # The override may name itself; its own proof script and docs may explain it. Anything
    # ELSE that composes it up is what this guards against.
    allowed = {
        EXPOSURE_OVERRIDE.resolve(),
        (REPO / "docker" / "proof" / "c2_lab_proof.sh").resolve(),
    }
    offenders: list[str] = []
    for path in REPO.rglob("*"):
        if not path.is_file() or path.resolve() in allowed:
            continue
        if any(part in {".git", "node_modules", ".venv", "__pycache__"} for part in path.parts):
            continue
        if path.suffix.lower() not in {".sh", ".yml", ".yaml", ".ps1", ".py", ".bat", ".cmd"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle not in text:
            continue
        # Documentation and this very test may NAME the file; only an actual `docker compose`
        # invocation that composes it in is an offender.
        for lineno, line in enumerate(text.splitlines(), start=1):
            if needle in line and "compose" in line and "-f" in line:
                offenders.append(f"{path.relative_to(REPO)}:{lineno}")
    assert not offenders, (
        "the opt-in exposure override is composed up by something other than its own proof "
        f"script — exposure must be explicit every time. Offenders: {offenders}"
    )
    print("  no script silently composes the exposure override into the default bring-up: PASS")


def test_the_scanner_actually_catches_a_wildcard() -> None:
    """The three tests above all print PASS when they work AND when the scan is broken.

    Same discipline as test_scans.py: plant a violation and prove the parser sees it. Without
    this, a `published_ports` that silently returns [] would make every check above vacuous.
    """
    import tempfile  # noqa: PLC0415

    planted = (
        "services:\n"
        "  engage-sandbox:\n"
        "    ports:\n"
        '      - "0.0.0.0:53:53/udp"\n'
        '      - "8888:8888"\n'
    )
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "planted.yml"
        probe.write_text(planted, encoding="utf-8")
        entries = published_ports(probe)
        assert len(entries) == 2, f"the port scanner missed a planted entry: {entries}"
        assert entries[0][1] == "0.0.0.0:53:53/udp", entries
        assert entries[1][1] == "8888:8888", entries
        # And the bind rule rejects both.
        assert _IP_BOUND.match(entries[1][1]) is None, "a bare host:container must not pass"
        m = _IP_BOUND.match(entries[0][1])
        assert m and m.group("ip") in _WILDCARD_IPS, "0.0.0.0 must be recognised as a wildcard"

    # And an inline-list form, which the block scanner must not miss.
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "inline.yml"
        probe.write_text('services:\n  x:\n    ports: ["0.0.0.0:1:1"]\n', encoding="utf-8")
        assert published_ports(probe) == [(3, "0.0.0.0:1:1")], published_ports(probe)

    print("  the port scanner catches planted wildcard/bare/inline bindings: PASS")


if __name__ == "__main__":
    print("== published-port exposure invariants (build #10) ==")
    test_the_scanner_actually_catches_a_wildcard()
    test_default_compose_publishes_nothing()
    test_exposure_override_is_ip_bound()
    test_override_is_not_wired_into_the_default_path()
    print("all exposure-invariant tests passed")
    sys.exit(0)
