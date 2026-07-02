import asyncio
import json
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pymongo import MongoClient
import amcop_engine

app = FastAPI(title="AMCOP Advanced C2 Platform")

# Enable wide-open CORS so your browser doesn't block the stream
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. FIX: Define a single global MongoDB connection instance for the app
# Using 'localhost' instead of '127.0.0.1' to bypass Windows IPv6 resolution latency
client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=1000)
db = client["amcop_platform"]
collection = db["operation_logs"]  # FIX: Corrected collection alignment

def fetch_operational_history_sync():
    """Synchronous helper to pull logs for the fallback/initial state."""
    try:
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
        print(f"[⚠️ DB CACHE FALLBACK] Could not reach MongoDB: {e}")
        return {"logs": [], "metrics": {"total": 0, "resilient": 0, "vulnerable": 0, "catch_rate": 0}}

@app.get("/", response_class=HTMLResponse)
async def serve_tactical_dashboard():
    """Serves the frontend workspace panel."""
    try:
        with open("templates/dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading templates/dashboard.html: {e}</h3>", status_code=500)

@app.get("/stream-telemetry")
async def stream_telemetry():
    async def event_generator():
        while True:
            # 2. FIX: Run the synchronous PyMongo query inside a threadpool 
            # to keep the async loop clear and prevent telemetry blocking.
            data = await run_in_threadpool(fetch_operational_history_sync)
            
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(1) # Keep telemetry pulse at 1Hz
            
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/execute-simulation/{technique_id}")
async def run_c2_simulation(technique_id: str):
    """Triggers the Red/Blue/White orchestration loop on-demand from the UI."""
    print(f"\n[🎮 C2 CONTROLLER] Received web trigger for MITRE Technique: {technique_id}")
    
    # Run the engine inside our threadpool so the UI doesn't lag while SSH executes
    await run_in_threadpool(amcop_engine.trigger_manual_simulation, technique_id)
    
    return {"status": "LAUNCHED", "technique": technique_id}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("[*] Activating Advanced Multi-Agent C2 Server Engine...")
    print("[*] Dashboard Link: http://localhost:5000")
    print("="*60 + "\n")
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)