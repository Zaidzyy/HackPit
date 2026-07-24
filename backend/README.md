# HackPit backend

FastAPI service: the built KB + hybrid search, guided attack-path composition, engagement
sessions + report generation, and the **Cockpit** (live, human-approved execution against an
isolated lab). Provider-swappable LLM layer (`llm.py`; default local Ollama).

## Run

```sh
cd backend
.venv/Scripts/python -m uvicorn main:app --reload    # http://localhost:8000
```

The Cockpit needs the isolated Docker stack up (sandbox + lab target):

```sh
docker compose -f docker/docker-compose.yml up -d
```

## Safety invariants — one command to re-verify

The Cockpit's safety model is four independent gates, enforced in order (see
`docs/cockpit-plan.md` §c):

1. **allowlist** — only the recon-only set (`nmap`/`curl`/`whatweb`), no shell metacharacters,
   per-command arg rules;
2. **target-lock** — the lab (`hackpit-lab-target`) must be the only host addressed;
3. **approval** — `approved` must be explicitly `true` (no autonomous / approve-all path);
4. **isolation** — the running sandbox must be attached ONLY to `internal` Docker networks;
   a single non-internal (egress) network makes it refuse to execute.

These are regression-locked by automated tests that **fail loudly** if the model is weakened:

```sh
sh backend/run_safety_tests.sh              # hermetic (no Docker): gates + composer regressions
sh backend/run_safety_tests.sh --with-proof # + the live structural isolation proof (stack must be up)
```

- `test_cockpit.py` — the four gates + gate ordering. The isolation gate is exercised by
  simulating `docker inspect` (both the safe internal-only case and the unsafe non-internal case),
  so the hermetic run needs no daemon.
- `test_attack_path.py` — composer regressions (meta-doc exclusion, target substitution scoping,
  `target_adaptation` guardrail, priority-class coverage).
- `test_engagement.py` — the M3 engagement/report path: a cockpit run is recorded against a session
  and listed back read-only, and the report folds the run's command + verbatim output into the
  authoritative Evidence section (cited by run id) while surfacing out-of-scope hosts. Hermetic
  (throwaway temp DB, no live LLM).
- `docker/proof/isolation_proof.sh` — the live structural proof: the sandbox reaches the lab and
  nothing else (no default route off the `internal:true` bridge). Must exit 0.

Expanding the allowlist, changing the target-lock, or relaxing a gate is a **deliberate, reviewed**
change — the tests above are designed to break first if it happens by accident.
