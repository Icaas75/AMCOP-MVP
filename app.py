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


def fetch_operational_history_sync():
    """Synchronous helper to pull logs for the fallback/initial state."""
    try:
        client = config.get_mongo_client()
        collection = client[config.MONGO_DB][config.MONGO_COLLECTION]

        raw_logs = list(collection.find().sort("_id", -1).limit(50))

        total = len(raw_logs)
        resilient = sum(1 for log in raw_logs if log.get("system_resilience") == "RESILIENT")
        vulnerable = total - resilient
        catch_rate = round((resilient / total) * 100) if total > 0 else 0

        for log in raw_logs:
            if "_id" in log:
                log["_id"] = str(log["_id"])

        return {
            "logs": raw_logs,
            "metrics": {
                "total": total,
                "resilient": resilient,
                "vulnerable": vulnerable,
                "catch_rate": catch_rate
            }
        }
    except Exception as e:
        print(f"[DB CACHE FALLBACK] Could not reach MongoDB: {e}")
        return {"logs": [], "metrics": {"total": 0, "resilient": 0, "vulnerable": 0, "catch_rate": 0}}


@app.get("/", response_class=HTMLResponse)
async def serve_tactical_dashboard():
    """Serves the frontend workspace panel."""
    try:
        return HTMLResponse(content=DASHBOARD_PATH.read_text(encoding="utf-8"), status_code=200)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading dashboard: {e}</h3>", status_code=500)


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
