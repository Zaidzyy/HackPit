"""Canonical knowledge-base schema for HackPit.

Every knowledge source (this source now; HackTricks, personal notes with images,
etc. later) normalizes into `Entry`. The schema is intentionally source-agnostic:
source-specific metadata that doesn't fit a canonical field is preserved in
`meta` rather than dropped, so future sources lose nothing.

Run `python pipeline/schema.py` to (re)emit the JSON Schema to
`pipeline/entry.schema.json`.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


class Code(BaseModel):
    """A single copyable code/command block attached to a step."""

    lang: str = Field(default="bash", description="Language / shell of the block.")
    cmd: str = Field(description="The command or code text.")
    copyable: bool = Field(default=True, description="Render with a copy button.")


class Step(BaseModel):
    """One ordered step of a technique, playbook, or checklist item."""

    n: int = Field(description="1-based position within the entry.")
    text: str = Field(default="", description="Human-readable instruction.")
    code: list[Code] = Field(default_factory=list, description="Copyable commands.")
    images: list[str] = Field(
        default_factory=list, description="Image paths/URLs illustrating the step."
    )


class Entry(BaseModel):
    """The canonical knowledge-base entry — one normalized document."""

    id: str = Field(description="Stable, unique slug for this entry.")
    title: str
    category: str = Field(
        description="Top-level bucket, e.g. web, active-directory, recon, "
        "privesc, services, tools."
    )
    subcategory: str | None = Field(default=None)
    source: str = Field(description="Origin knowledge source slug.")
    tier: int = Field(default=2, description="Trust ranking (lower = more trusted).")
    tags: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    summary: str = Field(default="", description="Short one-paragraph summary.")
    steps: list[Step] = Field(default_factory=list)
    body_md: str = Field(default="", description="Full normalized markdown body.")
    references: list[str] = Field(
        default_factory=list, description="Reference URLs."
    )
    # Extension point so future sources (and this one's extras like os/phase/
    # techniques/related-links) keep their metadata without bloating the
    # canonical fields above.
    meta: dict = Field(default_factory=dict)
    schema_version: str = Field(default=SCHEMA_VERSION)


def emit_json_schema(path: Path | str) -> Path:
    """Write the JSON Schema for `Entry` to `path` and return it."""
    path = Path(path)
    schema = Entry.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "HackPit Knowledge Entry"
    schema["x-schema-version"] = SCHEMA_VERSION
    path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    return path


if __name__ == "__main__":
    out = emit_json_schema(Path(__file__).with_name("entry.schema.json"))
    print(f"Wrote JSON Schema -> {out}")
