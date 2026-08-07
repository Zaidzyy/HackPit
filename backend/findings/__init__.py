"""Finding pipeline — dynamic schema, de-duplication, pluggable severity rankers, post-scripts.

The finding-processing machinery ported from open·kritt (the operator's own tool), adapted to
HackPit's approve-every-command model. It strengthens findings across EVERY surface — recon,
nuclei, AD, cloud, code-audit, manual paste — not one producer.

  schema.py       a dynamic/structured finding schema (validate + coerce arbitrary producers)
  pipeline.py     automatic de-duplication + IMPACT_LEVELS-ranked assembly (idempotent)
  rankers.py      pluggable, per-engagement severity rankers + shipped defaults
  postscripts.py  a post-finding hook: validate / report (data, in-process) / PoC (approve-each)

THE ONE INVARIANT: this package is PURE DATA. It executes nothing, opens no socket, and imports
no cockpit / executor / engagement / state module. Data operations run freely; a command
post-script returns an approve-each PROPOSAL that the app layer routes through the gated
executor. ``test_finding_pipeline_safety.py`` locks this from the outside.
"""

from __future__ import annotations

from . import pipeline, postscripts, rankers, schema

__all__ = ["schema", "pipeline", "rankers", "postscripts"]
