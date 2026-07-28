"""The reasoning copilot — a DEEPER proposer, not more autonomy.

Every module here produces proposals, scores, critiques and prompt text. NONE of them executes a
command, approves one, reaches the executor / :kali / sandbox, or holds any capability to run.
The proposer got smarter; the human still approves every single command. That split is
regression-locked by test_loop.py's source scan over this whole package.

  schema      2.2  hypothesis-first proposal shape + the invariant-3 citation gate
  ledger      2.1  working memory: tried/failed ledger + persisted dead leads
  frontier    2.3  candidate leads, scored, persisted; dead-end recovery (NOT a run queue)
  diagnosis   2.4  failure -> a diagnostic/alternative, never a blind repeat
  critic      2.5  refute-first pass; kills version-mismatched CVE hallucination
  specialists 2.6  route to a web / AD / binary-pwn / privesc expert instead of one generalist
  retrieval   2.7  fingerprint-keyed KB retrieval (case-based) ahead of token matches
  tiering     2.8  model-tier routing as a config lever, default inert
"""

from __future__ import annotations

from . import (  # noqa: F401
    critic,
    diagnosis,
    frontier,
    ledger,
    privesc,
    retrieval,
    schema,
    specialists,
    tiering,
    webexploit,
)


def init_db() -> None:
    """Create the reasoning tables (frontier + dead leads). Idempotent; safe on every startup."""
    ledger.init_db()
    frontier.init_db()
