"""Who is running HackPit — the one place operator identity is configured.

WHY THIS IS A CONFIG FILE AND NOT A CONSTANT: this repo is public (see the first
line of .gitignore — "ship CODE ONLY"). A real name, email or OSID written into
source is in the public git history permanently, and deleting it later does not
remove it. So identity lives in `operator.json` beside this module, gitignored
exactly like `llm_config.json`, with env overrides for containerised runs.

TWO AUDIENCES, DELIBERATELY DIFFERENT:

* `public_profile()` — what the BROWSER may see. Name and handle only. The web UI
  wants a byline; it has no business knowing an OSID or an email address.
* `report_identity()` — what goes into a REPORT you hand to an examiner or a
  triager. That document legitimately needs the identifying fields, which is the
  entire reason they are stored at all.

Keeping them separate means adding a field to the report can never leak it to a
page by accident. `test_operator.py` asserts the split against the real config.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(__file__).with_name("operator.json")

# Every field is optional. An unset HackPit renders no byline and no report
# identity block at all, rather than a half-filled one with empty labels.
DEFAULTS: dict[str, str] = {
    "name": "",      # display name shown as the intro byline
    "handle": "",    # platform handle, e.g. a HackerOne / GitHub username
    "osid": "",      # OSCP student id — REPORT ONLY, never sent to the browser
    "email": "",     # contact address — REPORT ONLY, never sent to the browser
}

_ENV = {
    "name": "HACKPIT_OPERATOR_NAME",
    "handle": "HACKPIT_OPERATOR_HANDLE",
    "osid": "HACKPIT_OPERATOR_OSID",
    "email": "HACKPIT_OPERATOR_EMAIL",
}


def _read_config_file() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:  # noqa: BLE001 - a malformed file must not break the app
            pass
    return {}


def load() -> dict[str, str]:
    """Effective identity: defaults -> file -> env (env wins), all trimmed."""
    cfg = dict(DEFAULTS)
    for key, value in _read_config_file().items():
        if key in cfg and isinstance(value, str):
            cfg[key] = value
    for key, env_name in _ENV.items():
        if os.environ.get(env_name):
            cfg[key] = os.environ[env_name]
    return {k: v.strip() for k, v in cfg.items()}


def public_profile() -> dict[str, str]:
    """Identity safe to return to the BROWSER — name and handle only.

    `osid` and `email` are deliberately absent. They exist for a report document
    handed to an examiner, not for a web page, and a page has no use for them.
    """
    cfg = load()
    return {"name": cfg["name"], "handle": cfg["handle"]}


def report_identity(template: str = "standard") -> str:
    """The "prepared by" block for a report, or "" when nothing is configured.

    Shaped per template, because the identifying field that matters differs:
    an OSCP submission is keyed on the OSID, a bug-bounty report on the handle.
    Returns Markdown, spliced under the report's title by `report.compose_report`.
    """
    cfg = load()
    tmpl = (template or "standard").strip().lower()

    rows: list[tuple[str, str]] = []
    if cfg["name"]:
        rows.append(("Prepared by", cfg["name"]))

    if tmpl == "oscp":
        # The exam submission is keyed on the OSID — without it the report is not
        # attributable to a candidate.
        if cfg["osid"]:
            rows.append(("OSID", cfg["osid"]))
    elif tmpl == "bugbounty":
        if cfg["handle"]:
            rows.append(("Handle", cfg["handle"]))
    else:
        if cfg["handle"]:
            rows.append(("Handle", cfg["handle"]))

    if cfg["email"]:
        rows.append(("Contact", cfg["email"]))

    if not rows:
        return ""

    lines = [f"**{label}:** {value}  " for label, value in rows]
    return "\n".join(lines)
