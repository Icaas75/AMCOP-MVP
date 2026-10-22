import asyncio
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool

import config
import amcop_engine

app = FastAPI(title="AMCOP Advanced C2 Platform")

# CORS is only installed when explicitly configured. The dashboard is served
# same-origin from this app, so the default (empty) means no CORS middleware at
# all -- no wide-open allow_origins=["*"] attack surface.
if config.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

DASHBOARD_PATH = Path(__file__).resolve().parent / "templates" / "dashboard.html"


HISTORY_WINDOW = 50  # metrics are computed over the most recent N cycles


def compute_metrics(raw_logs):
    """Evaluation-integrity metrics over a window of cycle records.

    catch_rate -- denominator: ALL cycles in the window, including execution
    failures (CONNECTION_ERROR etc.) and telemetry errors. It measures the
    fraction of attempted simulations that ended RESILIENT (attack executed
    AND detected). It is NOT a comprehensive detection rate: it mixes
    infrastructure failures into its denominator and the test design (four
    pre-signatured techniques) does not cover novel attacks.

    detection_rate -- denominator: cycles where the attack actually executed
    (ground truth positive, red_outcome == SUCCESS). That is the honest
    true-positive rate for the detection pipeline. Records without
    red_outcome/blue_outcome (legacy) are excluded.
    """
    total = len(raw_logs)
    resilient = sum(1 for log in raw_logs if log.get("system_resilience") == "RESILIENT")
    vulnerable = total - resilient
    catch_rate = round((resilient / total) * 100) if total > 0 else 0

    from collections import Counter
    confusion = Counter()
    for log in raw_logs:
        red, blue = log.get("red_outcome"), log.get("blue_outcome")
        if red is None or blue is None:
            continue  # legacy record: not classifiable
        confusion[amcop_engine.classify_detection(red, blue)] += 1
    # Zero-fill known classes so the shape is stable for consumers.
    for key in ("TP", "FN", "FP_SUSPECTED", "TN", "UNSCORED",
                "UNSCORED_TELEMETRY_ERROR"):
        confusion.setdefault(key, 0)

    ground_truth_positive = confusion["TP"] + confusion["FN"]
    detection_rate = (round((confusion["TP"] / ground_truth_positive) * 100)
                      if ground_truth_positive > 0 else None)

    return {
        "total": total,
        "resilient": resilient,
        "vulnerable": vulnerable,
        "catch_rate": catch_rate,
        "confusion": confusion,
        "detection_rate": detection_rate,  # None = no ground-truth-positive cycles
        "window": HISTORY_WINDOW,
    }


def fetch_operational_history_sync():
    """Synchronous helper to pull logs for the fallback/initial state."""
    try:
        client = config.get_mongo_client()
        collection = client[config.MONGO_DB][config.MONGO_COLLECTION]

        raw_logs = list(collection.find().sort("_id", -1).limit(HISTORY_WINDOW))

        for log in raw_logs:
            if "_id" in log:
                log["_id"] = str(log["_id"])

        return {"logs": raw_logs, "metrics": compute_metrics(raw_logs)}
    except Exception as e:
        print(f"[DB CACHE FALLBACK] Could not reach MongoDB: {e}")
        return {"logs": [], "metrics": compute_metrics([])}


@app.get("/", response_class=HTMLResponse)
async def serve_tactical_dashboard():
    """Serves the frontend workspace panel."""
    try:
        return HTMLResponse(content=DASHBOARD_PATH.read_text(encoding="utf-8"), status_code=200)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading dashboard: {e}</h3>", status_code=500)


@app.get("/assessment-report")
async def assessment_report():
    """Persistent, readable assessment summary built from recorded cycles.

    Derived strictly from MongoDB records -- no invented scores or verdicts.
    Gaps are computed from observed outcomes (missed detections, execution
    failures, techniques never attempted).
    """
    def _build_sync():
        try:
            client = config.get_mongo_client()
            collection = client[config.MONGO_DB][config.MONGO_COLLECTION]
            logs = list(collection.find().sort("_id", -1).limit(500))
        except Exception as e:
            print(f"[ASSESSMENT REPORT] MongoDB unavailable: {e}")
            logs = []

        # SHARED METRIC DEFINITION: headline metrics use the exact same window
        # as /stream-telemetry (most recent HISTORY_WINDOW cycles), so the
        # dashboard gauge and this report can never diverge on denominator.
        metrics = compute_metrics(logs[:HISTORY_WINDOW])

        per_technique = {}
        unrecognized_records = 0
        for log in logs:
            tech = log.get("mitre_technique", "UNKNOWN")
            if tech not in amcop_engine.TECHNIQUES:
                # Historical/invalid IDs (e.g. NOT-A-TECHNIQUE) are counted but
                # must NOT appear as technique coverage. History is preserved.
                unrecognized_records += 1
                continue
            t = per_technique.setdefault(tech, {
                "technique_name": log.get("technique_name"),
                "attempted": 0, "executed": 0, "detected": 0, "missed": 0,
                "execution_failures": 0,
            })
            t["attempted"] += 1
            red, blue = log.get("red_outcome"), log.get("blue_outcome")
            if red == "SUCCESS":
                t["executed"] += 1
                if blue == "DETECTED":
                    t["detected"] += 1
                elif blue == "MISSED":
                    t["missed"] += 1
            elif red in ("FAILED", "CONNECTION_ERROR", "COMMAND_TIMEOUT"):
                t["execution_failures"] += 1

        never_attempted = sorted(set(amcop_engine.TECHNIQUES) - set(per_technique))

        gaps = []
        if unrecognized_records:
            gaps.append(f"{unrecognized_records} historical record(s) with "
                        f"unregistered technique IDs (excluded from technique "
                        f"coverage; preserved, not deleted)")
        for tech, t in per_technique.items():
            if t["missed"] > 0:
                gaps.append(f"{tech}: {t['missed']} executed cycle(s) not detected "
                            f"(detection rules missed observed evidence)")
            if t["execution_failures"] > 0:
                gaps.append(f"{tech}: {t['execution_failures']} execution failure(s) "
                            f"(infrastructure, not a detection failure)")
        if never_attempted:
            gaps.append(f"Techniques implemented but not yet attempted: "
                        f"{', '.join(never_attempted)}")
        if metrics["confusion"]["FP_SUSPECTED"] > 0:
            gaps.append(f"{metrics['confusion']['FP_SUSPECTED']} flag(s) raised without "
                        f"a successful attack execution (possible false positives; "
                        f"Blue decisions from held-open SSH sessions)")

        return {
            "generated_from_cycles": len(logs),
            "window": HISTORY_WINDOW,
            "metrics": metrics,
            "unrecognized_records": unrecognized_records,
            "per_technique": per_technique,
            "gaps": gaps,
            "limitations": [
                "Detection is rule-based over `ps aux` snapshots, not ML; only "
                "implemented techniques can be detected by signature.",
                "detection_latency_ms includes the fixed 1s observation window.",
                "FP_SUSPECTED entries are flagged-not-executed cycles; the lab "
                "holds Red's SSH session open, which Rule C legitimately fires on.",
                "Live detections are driven by the held-open SSH session "
                "indicator (Rule C). Technique-specific recon rules (Rule A) "
                "are unit-tested on fixtures, but payload processes normally "
                "complete before the ps aux snapshot, so rule attribution per "
                "technique is not claimed from live data.",
                "Headline metrics cover the most recent "
                f"{HISTORY_WINDOW} cycles (same window as the dashboard "
                "gauge); per-technique counts cover up to 500 records.",
            ],
        }

    return await run_in_threadpool(_build_sync)


@app.get("/health")
async def health():
    """Liveness/readiness probe: reports datastore reachability."""
    db_ok = False
    try:
        client = config.get_mongo_client()
        client.admin.command("ping")
        db_ok = True
    except Exception:
        pass
    return {"status": "OK", "database": "UP" if db_ok else "DOWN"}


@app.get("/stream-telemetry")
async def stream_telemetry():
    async def event_generator():
        while True:
            # Run the synchronous PyMongo query inside a threadpool to keep the
            # async loop clear and prevent telemetry blocking.
            data = await run_in_threadpool(fetch_operational_history_sync)

            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(1)  # Keep telemetry pulse at 1Hz

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/execute-simulation/{technique_id}")
async def run_c2_simulation(technique_id: str):
    """Triggers the Red/Blue/White orchestration loop on-demand from the UI."""
    # API-boundary validation: only registered MITRE technique IDs are
    # accepted. This prevents invalid IDs (e.g. NOT-A-TECHNIQUE) from being
    # recorded as coverage of a real technique via the payload fallback.
    if technique_id not in amcop_engine.TECHNIQUES:
        return JSONResponse(
            status_code=422,
            content={"status": "ERROR", "technique": technique_id,
                     "detail": "Unknown technique ID; not in the registered "
                               "technique registry.",
                     "registered": sorted(amcop_engine.TECHNIQUES)},
        )

    print(f"\n[C2 CONTROLLER] Received web trigger for MITRE Technique: {technique_id}")

    try:
        # Run the engine inside our threadpool so the UI doesn't lag while SSH executes
        report = await run_in_threadpool(amcop_engine.trigger_manual_simulation, technique_id)
    except Exception as e:
        # Never leak internals; return a clean, testable error contract.
        print(f"[C2 CONTROLLER] Simulation cycle failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "ERROR", "technique": technique_id,
                     "detail": "Simulation cycle failed; check server logs and lab containers."},
        )

    return {
        "status": "LAUNCHED",
        "technique": technique_id,
        "result": {
            "red_outcome": report.get("red_outcome"),
            "blue_outcome": report.get("blue_outcome"),
            "system_resilience": report.get("system_resilience"),
        },
    }


if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print("[*] Activating Advanced Multi-Agent C2 Server Engine...")
    print(f"[*] Dashboard Link: http://{config.APP_HOST}:{config.APP_PORT}")
    print("=" * 60 + "\n")
    uvicorn.run("app:app", host=config.APP_HOST, port=config.APP_PORT, reload=False)
