"""HackPit backend — FastAPI service.

Scaffolding only. Feature endpoints (companion, then cockpit) are added later.
"""

from fastapi import FastAPI

app = FastAPI(title="HackPit API", version="0.0.1")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
