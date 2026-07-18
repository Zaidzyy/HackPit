"""Image content extraction for HackPit notes ingestion.

A lot of the knowledge in the course notes lives *inside* screenshots (terminal
output, Burp requests, commands). This module turns those images into searchable
text so the notes ingester (built next) can attach it to entries.

Pipeline per image:
    1. tesseract OCR  -> ocr_text
    2. classify       -> kind = "terminal" (dense text) | "gui" (sparse)
    3. GUI / low-text -> local Ollama vision model caption (free, offline)
    4. cache          -> data/images/captions.json  (gitignored)

Design notes:
    * Images are read from an EXTERNAL path and never copied into the repo.
    * Results are cached; a re-run skips already-processed images (unless
      --force). The cache is written after every image, so a crash keeps
      progress.
    * One bad image never aborts the run: it is recorded ok=false and we
      continue.

Usage:
    uv run python images.py                 # process all, using cache
    uv run python images.py --force         # reprocess everything
    uv run python images.py --limit 5       # first 5 (smoke test)
    uv run python images.py --no-vision     # OCR only, skip captions
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import shutil
import subprocess
import urllib.request
from pathlib import Path

DEFAULT_NOTES_PATH = r"C:\Users\zaid_\Downloads\hacks\PRACTICAL ETHICAL HACKING COMPLETE NOTES"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "data" / "images"
# Hand-authored caption overrides (committed — our own tiny authored text).
# Where a note image is present here, this verified caption is preferred over
# the local vision-model (llava) caption, which can hallucinate.
MANUAL_CAPTIONS = Path(__file__).with_name("manual_captions.json")
OLLAMA_HOST = "http://localhost:11434"

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

# Classification thresholds (heuristic — OCR char/line density).
DENSE_CHARS = 200          # >= this many chars of OCR  => clearly a text screenshot
DENSE_LINES = 8            # this many lines + moderate chars also counts as dense
DENSE_LINES_CHARS = 120
LOW_TEXT_CHARS = 120       # below this we always want a vision caption

VISION_PROMPT = (
    "This is a screenshot from a penetration-testing / ethical-hacking course. "
    "In 1-3 concise, factual sentences describe what it shows: the tool or "
    "interface (e.g. Burp Suite, nmap, a browser, a diagram), the action being "
    "performed, and any key values visible (hostnames, IPs, usernames, ports, "
    "commands, or findings). Do not speculate beyond what is visible."
)

# Preference order for the local vision model.
VISION_MODEL_PREFS = ("llama3.2-vision", "llava", "bakllava", "qwen2.5vl", "moondream")


# --------------------------------------------------------------------------- #
# tooling discovery
# --------------------------------------------------------------------------- #
def find_tesseract() -> str | None:
    """Locate the tesseract binary: PATH, then common install dirs."""
    exe = shutil.which("tesseract")
    if exe:
        return exe
    candidates = [
        Path.home() / "scoop/shims/tesseract.exe",
        Path.home() / "scoop/apps/tesseract/current/tesseract.exe",
        Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
        Path(r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"),
        Path.home() / "AppData/Local/Programs/Tesseract-OCR/tesseract.exe",
        Path(r"C:\ProgramData\chocolatey\bin\tesseract.exe"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def list_ollama_models(host: str) -> list[str]:
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=6) as r:
            data = json.loads(r.read())
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def vision_candidates(host: str) -> list[str]:
    """All installed vision-capable models, most-preferred first."""
    models = list_ollama_models(host)
    ordered: list[str] = []
    for pref in VISION_MODEL_PREFS:
        for m in models:
            if (m == pref or m.startswith(pref + ":")) and m not in ordered:
                ordered.append(m)
    for m in models:  # catch-all for other vision-looking names
        low = m.lower()
        if m not in ordered and any(
            k in low for k in ("vision", "llava", "-vl", "moondream")
        ):
            ordered.append(m)
    return ordered


def warmup_ok(host: str, model: str) -> tuple[bool, str]:
    """Try to load a model; returns (ok, error). Catches runtime-arch failures
    like llama3.2-vision's 'mllama' not being supported by the local runner."""
    payload = {"model": model, "prompt": "ok", "stream": False,
               "options": {"num_predict": 1}}
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=600):
            return True, ""
    except urllib.error.HTTPError as e:
        return False, e.read().decode("utf-8", "replace")[:200]
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def pick_vision_model(host: str, override: str | None = None) -> str | None:
    """Pick the first installed vision model that actually loads."""
    candidates = [override] if override else vision_candidates(host)
    for m in candidates:
        ok, err = warmup_ok(host, m)
        if ok:
            return m
        print(f"  vision model '{m}' unusable, skipping: {err}")
    return None


# --------------------------------------------------------------------------- #
# extraction steps
# --------------------------------------------------------------------------- #
def run_ocr(tesseract: str, img: Path) -> str:
    """Run tesseract to stdout; return decoded text ('' on soft failure)."""
    proc = subprocess.run(
        [tesseract, str(img), "stdout", "-l", "eng"],
        capture_output=True,
        timeout=180,
    )
    return proc.stdout.decode("utf-8", errors="replace").strip()


def classify(ocr_text: str) -> tuple[str, int]:
    text = ocr_text.strip()
    char_count = len(text)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    dense = char_count >= DENSE_CHARS or (
        len(lines) >= DENSE_LINES and char_count >= DENSE_LINES_CHARS
    )
    return ("terminal" if dense else "gui"), char_count


def ollama_caption(host: str, model: str, img: Path) -> str:
    b64 = base64.b64encode(img.read_bytes()).decode("ascii")
    payload = {
        "model": model,
        "prompt": VISION_PROMPT,
        "images": [b64],
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 180},
    }
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        data = json.loads(r.read())
    return (data.get("response") or "").strip()


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def find_images(notes_path: Path) -> list[Path]:
    return sorted(
        p for p in notes_path.rglob("*") if p.suffix.lower() in IMAGE_EXTS
    )


def load_manual_captions(path: Path = MANUAL_CAPTIONS) -> dict[str, str]:
    """Load committed manual caption overrides -> {image_rel_path: caption}.

    Missing file is fine (returns {}). Supports both the wrapped form
    ``{"captions": {...}}`` and a bare ``{path: caption}`` mapping.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    caps = data.get("captions", data) if isinstance(data, dict) else {}
    return {str(k): str(v) for k, v in caps.items() if not str(k).startswith("_")}


def apply_manual_overrides(images: dict, manual: dict[str, str]) -> int:
    """Force every image present in `manual` to use the authored caption.

    Runs across the whole cache (including images skipped this run) so a manual
    caption always wins over any previously-stored llava caption.
    """
    applied = 0
    for rel, caption in manual.items():
        rec = images.get(rel)
        if rec is None:
            continue
        rec["caption"] = caption
        rec["caption_source"] = "manual"
        rec.pop("caption_error", None)
        applied += 1
    return applied


def load_cache(out_file: Path) -> dict:
    if out_file.exists():
        try:
            return json.loads(out_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"meta": {}, "images": {}}


def save_cache(out_file: Path, cache: dict) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(
        json.dumps(cache, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def process(
    notes_path: Path,
    out_dir: Path,
    host: str,
    use_vision: bool,
    force: bool,
    limit: int | None,
    model_override: str | None = None,
) -> dict:
    tesseract = find_tesseract()
    if not tesseract:
        raise SystemExit(
            "tesseract not found. Install it (see README) or set it on PATH."
        )

    model = pick_vision_model(host, model_override) if use_vision else None
    if use_vision and not model:
        print("WARNING: no local vision model found — captions disabled.")

    out_file = out_dir / "captions.json"
    cache = load_cache(out_file)
    images = cache.setdefault("images", {})
    manual = load_manual_captions()

    all_imgs = find_images(notes_path)
    if limit:
        all_imgs = all_imgs[:limit]

    processed = skipped = failed = 0
    for i, img in enumerate(all_imgs, 1):
        rel = img.relative_to(notes_path).as_posix()
        if not force and rel in images and images[rel].get("ok") is not None:
            skipped += 1
            continue

        rec = {"ocr_text": "", "caption": "", "kind": None,
               "char_count": 0, "ok": False}
        try:
            ocr_text = run_ocr(tesseract, img)
            kind, char_count = classify(ocr_text)
            rec.update(ocr_text=ocr_text, kind=kind, char_count=char_count)

            override = manual.get(rel)
            if override is not None:
                # Authored caption wins — don't spend a vision-model call.
                rec["caption"] = override
                rec["caption_source"] = "manual"
            else:
                want_caption = use_vision and model and (
                    kind == "gui" or char_count < LOW_TEXT_CHARS
                )
                if want_caption:
                    try:
                        rec["caption"] = ollama_caption(host, model, img)
                        rec["caption_source"] = "llava"
                    except Exception as exc:  # caption is best-effort
                        rec["caption_error"] = f"{type(exc).__name__}: {exc}"

            rec["ok"] = bool(rec["ocr_text"] or rec["caption"])
        except Exception as exc:  # OCR / read failure — record and continue
            rec["error"] = f"{type(exc).__name__}: {exc}"
            rec["ok"] = False

        images[rel] = rec
        processed += 1
        if not rec["ok"]:
            failed += 1
        tag = rec["kind"] or "err"
        cap = " +caption" if rec.get("caption") else ""
        print(f"[{i}/{len(all_imgs)}] {tag:8} {rec['char_count']:>5}c{cap}  {rel}")
        save_cache(out_file, cache)  # incremental — survive crashes

    # Manual overrides win over any stored llava caption, even for images that
    # were skipped (already cached) this run.
    overridden = apply_manual_overrides(images, manual)

    cache["meta"] = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "notes_path": str(notes_path),
        "tesseract": tesseract,
        "vision_model": model,
        "total_images": len(all_imgs),
        "manual_overrides": overridden,
    }
    save_cache(out_file, cache)

    return {
        "total": len(all_imgs),
        "processed": processed,
        "skipped": skipped,
        "failed": failed,
        "out_file": out_file,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract text/captions from note images.")
    ap.add_argument("--notes-path", default=DEFAULT_NOTES_PATH)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--host", default=OLLAMA_HOST)
    ap.add_argument("--no-vision", action="store_true", help="skip Ollama captions")
    ap.add_argument("--model", default=None, help="force a specific vision model")
    ap.add_argument("--force", action="store_true", help="reprocess cached images")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    notes_path = Path(args.notes_path)
    if not notes_path.is_dir():
        raise SystemExit(f"Notes path not found: {notes_path}")

    stats = process(
        notes_path=notes_path,
        out_dir=Path(args.out),
        host=args.host,
        use_vision=not args.no_vision,
        force=args.force,
        limit=args.limit,
        model_override=args.model,
    )
    print(
        f"\nDone. total={stats['total']} processed={stats['processed']} "
        f"skipped={stats['skipped']} failed={stats['failed']} "
        f"-> {stats['out_file']}"
    )


if __name__ == "__main__":
    main()
