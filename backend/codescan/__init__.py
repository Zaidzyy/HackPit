"""codescan — STATIC application-security analysis (SAST).

Reads a codebase and reports what the scanners find. It never executes the code it scans,
never touches a target, never opens a socket on the reviewer's behalf, and shares nothing
with the engagement / executor / target-lock / scope / isolation model. A self-contained
analysis utility that happens to live in the same backend.

See docs/CODE-SCAN.md.
"""

from .runner import (  # noqa: F401
    ScanError,
    ScannerMissing,
    ScanTimeout,
    available,
    resolve_target,
    run_bandit,
    run_semgrep,
)
