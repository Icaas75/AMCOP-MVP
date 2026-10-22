# AMCOP — Autonomous Multi-Agent Cyber Operation Platform

AMCOP is an automated cyber-range and continuous security-validation engine. An
autonomous three-agent framework executes **safe, simulated MITRE ATT&CK
discovery payloads** against a **containerized lab target**, collects real-time
kernel/process telemetry, evaluates defensive resilience, and streams live
metrics to a web dashboard.

> **Authorized lab only.** All simulations target a disposable local container
> on an isolated Docker bridge network with loopback-only port bindings. Never
> point AMCOP at systems you do not own or have explicit permission to test.

---

## Architecture

| Agent | Role | Mechanism |
|---|---|---|
| 🔴 Red AI | Adversary | SSH (`paramiko`) into the target container and executes a technique payload. The session is **kept open** during Blue's snapshot so the attacker's channel is observable. |
| 🔵 Blue AI | Defender | Reads `ps aux` from the live container over the Docker socket, scores behavioral rules (admin recon incl. `uname`/`ip addr`/`ifconfig`, evasion, non-TTY remote shells), and reports `DETECTED` / `MISSED` at a threshold of 40 — decided **only** from observed evidence, never from Red's self-report. |
| ⚪ White AI | Orchestrator | Runs Red → observation window → Blue, judges `RESILIENT` (attack succeeded **and** detected) vs `VULNERABLE`, classifies TP/FP/TN/FN against execution ground truth, records detection latency + rationale, persists the report to MongoDB. |

### Implemented techniques

| ID | Name | Payload (read-only recon) |
|---|---|---|
| T1087 | Account Discovery | `cat /etc/passwd` |
| T1049 | Network Connections Discovery | `netstat -an \|\| ss -tulpn` |
| T1082 | System Information Discovery | `uname -a` |
| T1016 | System Network Configuration Discovery | `ip addr \|\| ifconfig -a` |

Unknown IDs fall back to `uname -a`. Payloads execute only over SSH to the
loopback-bound lab container — no scanning, no lateral movement, no writes.

**Data flow:** dashboard button → `POST /execute-simulation/{technique}` →
Red/Blue/White cycle → MongoDB → `GET /stream-telemetry` (SSE, 1 Hz) → live
dashboard (ledger, consoles, catch-rate gauge, resilience chart).

```
.
├── app.py                 # FastAPI app: dashboard, SSE stream, simulation API
├── amcop_engine.py        # Red / Blue / White agent implementations
├── config.py              # env-driven configuration (+ .env loader)
├── templates/dashboard.html  # single-file React dashboard (CDN, no build step)
├── tests/                 # unit + API + guarded live integration tests
├── docker-compose.yml     # lab infrastructure (MongoDB + SSH target)
├── requirements.txt
└── .env.example           # configuration template (copy to .env)
```

---

## Prerequisites

- **Docker Desktop** (with Compose v2)
- **Python 3.10+** (developed and verified on 3.13 / Windows)
- ~2 minutes

---

## Installation (first run)

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Start lab infrastructure (MongoDB + target-node-01 on isolated network)
docker compose up -d

# 3. Configure (optional — lab defaults work out of the box)
copy .env.example .env        # Windows:  cp .env.example .env  on macOS/Linux
```

That's it — no manual provisioning step is needed: the compose file starts
the target with a self-provisioning command that installs `netstat`/`ss`
(needed by the T1049 payload) on first boot before `sshd` starts.

## Starting the application

```bash
python app.py
# or:  python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

Open **http://127.0.0.1:5000**

Health check: `curl http://127.0.0.1:5000/health` → `{"status":"OK","database":"UP"}`

## Running the tests

```bash
python -m unittest discover -s tests -v
```

- Unit + API tests are **hermetic** — they pass with Docker/MongoDB off.
- The two live integration tests **auto-skip** when the lab containers are down
  and run automatically when they are up.

---

## Demonstration procedure (~3 minutes)

1. `docker compose up -d` and `python app.py`.
2. Open http://127.0.0.1:5000 — confirm the header shows **SSE DATA LINK
   STABLE** and the catch-rate gauge renders (initial values from history or 0).
3. In **Tactical Control Array**, select `T1087 - Account Discovery`, click
   **Launch Attack Cycle** (~2–3 s). Expect:
   - **RED_AI console**: `root@target-node-01:~# cat /etc/passwd` + real output
   - **BLUE_AI console**: `Anomaly Score: 40/100` with a `RISK ALERT` for the
     rogue non-interactive shell (and/or admin recon)
   - **Ledger**: new row with green `RESILIENT`
4. Repeat with `T1049 - Net Connections Discovery`, then demonstrate the new
   coverage: `T1082 - System Information Discovery` (`uname -a`) and
   `T1016 - System Network Configuration Discovery` (`ip addr`) — expect the
   same RESILIENT result with recon evidence in the BLUE_AI console.
5. Point at the **Cyber Resilience Drift Timeline** (new 100 point appended)
   and the **catch-rate gauge** updating live with no page refresh.
6. Run the automated repeatability proof:

   ```bash
   python -m unittest tests.test_integration_live -v
   ```

   Both live tests pass: full-cycle consistency (report == MongoDB record) and
   3/3 cycles `SUCCESS/DETECTED/RESILIENT`.

### Verifying agreement (backend ↔ database ↔ dashboard)

```bash
# What the API just returned is echoed by the DB:
python -c "from pymongo import MongoClient; print(list(MongoClient('mongodb://localhost:27017/')['amcop_platform']['operation_logs'].find().sort('_id',-1).limit(1)))[0]['system_resilience']"

# What the dashboard receives over SSE:
curl -s -N http://127.0.0.1:5000/stream-telemetry | head -1
```

Both must show the same `system_resilience` for the newest cycle.

---

## Configuration

All settings are environment variables (or `.env` — real env always wins).
See **`.env.example`** for the full list: target host/port/credentials,
MongoDB URI, app host/port, CORS origins. Defaults match `docker-compose.yml`.

- The app binds to **127.0.0.1** and compose publishes ports on **127.0.0.1**
  only — nothing is exposed beyond your machine.
- **No CORS middleware** is installed by default (dashboard is same-origin).
  Set `AMCOP_CORS_ORIGINS` only if you front the app from another origin.
- Credentials live in `.env` (gitignored) — never in source, logs, or docs.

## Stopping the lab

```bash
docker compose down        # stop and remove lab containers
# then stop the app (Ctrl+C in the terminal running python app.py)
```

Data in MongoDB (or your local MongoDB) is preserved across stops. To return
to a clean slate: `docker compose down -v` (removes the compose volumes) —
this destroys stored simulation history, so only do it deliberately.

### Note: machine with an existing local MongoDB

If a MongoDB is **already listening on `127.0.0.1:27017`** on your machine
(e.g. installed as a system service), the compose `amcop-db` container cannot
bind that port and will exit with a bind error. In that case start only the
target and let AMCOP use your existing local MongoDB — the application will
work normally:

```bash
docker compose up -d target-node-01
```

On a machine without a local MongoDB, plain `docker compose up -d` starts both
services without error.

---

## Evaluation metrics — definitions

Every cycle record now stores evaluation-integrity fields:

- `technique_name`, `red_outcome`, `blue_outcome`, `system_resilience`
- `detection_evidence` — anomaly score, threshold, risk indicators, processes
  audited (Blue's decision input)
- `detection_rationale` — human-readable justification of the decision
- `detection_latency_ms` — Red payload launch → Blue decision complete;
  includes the fixed 1s observation window (pipeline delay, not dwell time)
- `confusion_class` — `TP` / `FN` / `FP_SUSPECTED` / `TN`, using execution
  ground truth (red `SUCCESS` = attack actually ran). Telemetry errors are
  `UNSCORED_TELEMETRY_ERROR`; execution failures are tracked separately from
  detection failures.

**`catch_rate`** (dashboard gauge) = RESILIENT cycles ÷ all cycles in the last
50 (`HISTORY_WINDOW`). Its denominator **includes execution failures and
telemetry errors**, so it is a platform-outcome rate, not a detection rate.

**`detection_rate`** (API `metrics.detection_rate` and `/assessment-report`)
= TP ÷ (TP + FN) — the true-positive rate over cycles where the attack
actually executed. `null` when no ground-truth-positive cycles exist.

Both headline metrics use the **same window** (`HISTORY_WINDOW = 50` most
recent cycles) in `/stream-telemetry` and `/assessment-report`, so the
dashboard gauge and the report can never disagree on the denominator.
Per-technique breakdowns in the report scan up to 500 records.

**Technique IDs are validated at the API boundary**: `POST
/execute-simulation/{id}` returns `422` for IDs not in the registry (the
engine is not invoked). Historical records with unregistered IDs (e.g.
`NOT-A-TECHNIQUE` from earlier sessions) are preserved but excluded from
technique coverage and reported under `unrecognized_records`.

**Detection evidence honesty**: in live operation every detected cycle fired
from Rule C (the adversary's held-open `sshd … notty` session), not from the
payload command itself — payload processes normally exit before the `ps aux`
snapshot. Rule A (technique-specific recon signatures such as `cat /etc`,
`netstat`, `uname`, `ip addr`) is implemented and unit-tested on fixtures,
but per-technique rule attribution is **not claimed from live data**.

## Assessment report

`GET /assessment-report` returns a persistent, readable summary computed
strictly from recorded MongoDB cycles (nothing invented): per-technique
attempted/executed/detected/missed/execution-failure counts, the confusion
matrix, both rates, data-derived gaps (missed detections, execution failures,
techniques never attempted) and evaluation limitations.

---

## Evaluation results (2026-10-22)

| Check | Result |
|---|---|
| `python -m unittest discover -s tests` | **49/49 pass** (incl. live integration) |
| Dashboard selector vs registry | **4/4 techniques selectable** (was 2; hardcoded list fixed) |
| Invalid technique ID at API | **422 rejected**, engine not invoked |
| Full cycle ×4 via API (T1087, T1049, T1082, T1016) | **4/4 `SUCCESS / DETECTED / RESILIENT`** |
| New techniques T1082/T1016 | verified live with evidence + TP classification |
| Repeatability (3 consecutive cycles, live test) | **3/3 DETECTED** |
| MongoDB ↔ API ↔ SSE agreement | Identical verdicts on newest records |
| `/health`, `/`, `/stream-telemetry`, `/assessment-report` | `200` / `200` / streaming 1 Hz / `200` |
| Windows Unicode crash on `/execute-simulation` | **Fixed** (UTF-8 console reconfigure) |
| Wildcard CORS / hardcoded secrets in code | **Removed** |

## Known limitations

1. **Detection is signature/rule-based**, not ML — fixed behavioral rules with
   a 40-point threshold; novel techniques won't be detected. Score capped at
   100 for display.
2. **False positives are possible**: any root `netstat`/`cat /etc`/`uname`
   process or non-TTY sshd session in the target scores as risk, regardless
   of intent. `FP_SUSPECTED` cycles in the report reflect this.
3. **Catch-rate gauge** uses all 50 recent cycles in its denominator,
   including historical pre-fix `VULNERABLE` and infrastructure-failure
   records; use `detection_rate` for the detection-pipeline view.
4. **Four techniques implemented** (T1087, T1049, T1082, T1016); unknown IDs
   are rejected at the API (`422`). Direct engine calls with unknown IDs fall
   back to `uname -a` (kept for compatibility; the API never passes them).
   Payloads are read-only discovery.
5. **SSE loop runs per client forever** — fine for a demo, would need a
   connection manager for many concurrent viewers.
6. **Dashboard loads React/Babel/Tailwind from CDN** at runtime; requires
   internet in the browser. In-browser Babel is dev-grade, not production.
7. **Plain-text SSH password auth** to the lab container (lab-only; the
   compose file binds port 2222 to loopback).
8. **Timestamps are second-granularity local time**; two cycles in the same
   second can share a `timestamp` field.
9. **Detection latency includes the fixed 1s observation window** (~1.3–1.4s
   observed); it measures platform pipeline delay, not attacker dwell time.

## Remaining submission blockers

- **None known.** All deliverables verified: reproducible app, 23 passing
  tests, corrected docs (this file), recorded results above, limitations
  documented. Optional polish left out by scope: CI workflow, pre-compiled
  frontend, connection-managed SSE.
