"""Central configuration for AMCOP.

All runtime values resolve from environment variables, optionally loaded from a
local ``.env`` file (never committed). No credentials live in source code.

The lab defaults match the disposable containers defined in docker-compose.yml
(rastasheep/ubuntu-sshd ships with root/root on an isolated bridge network).
Override them via .env for anything beyond the local authorized lab.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# --- Windows console fix -----------------------------------------------------
# The codebase prints Unicode status glyphs (RED/BLUE/WHITE markers). On Windows
# the default console codec (cp1252) raises UnicodeEncodeError on emoji, which
# crashed /execute-simulation with a 500. Force UTF-8 with replacement so prints
# can never take down a request handler.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (key=VALUE lines, # comments). setdefault semantics:
    real environment variables always win over the file."""
    env_path = PROJECT_ROOT / path
    if not env_path.is_file():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


_load_dotenv()


def env(name: str, default=None):
    return os.environ.get(name, default)


# --- Authorized lab target (containerized, isolated) -------------------------
TARGET_HOST = env("AMCOP_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(env("AMCOP_TARGET_PORT", "2222"))
TARGET_USER = env("AMCOP_TARGET_USER", "root")
TARGET_PASSWORD = env("AMCOP_TARGET_PASSWORD", "root")
TARGET_CONTAINER = env("AMCOP_TARGET_CONTAINER", "target-node-01")

# --- Datastore ---------------------------------------------------------------
MONGO_URI = env("AMCOP_MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = env("AMCOP_MONGO_DB", "amcop_platform")
MONGO_COLLECTION = env("AMCOP_MONGO_COLLECTION", "operation_logs")

# --- Web server --------------------------------------------------------------
APP_HOST = env("AMCOP_APP_HOST", "127.0.0.1")  # loopback only: lab boundary
APP_PORT = int(env("AMCOP_APP_PORT", "5000"))
# Comma-separated allowed origins. Empty (default) = CORS middleware not
# installed at all; the dashboard is served same-origin from this app.
CORS_ORIGINS = [o.strip() for o in env("AMCOP_CORS_ORIGINS", "").split(",") if o.strip()]

# --- AI-Assisted Incident Analyst (optional LLM integration) -----------------
# Feature degrades gracefully to "unavailable" when the key is absent.
# Any OpenAI-compatible chat-completions endpoint works via BASE_URL.
LLM_API_KEY = env("AMCOP_LLM_API_KEY", "")
LLM_MODEL = env("AMCOP_LLM_MODEL", "gpt-4o-mini")
LLM_BASE_URL = env("AMCOP_LLM_BASE_URL", "https://api.openai.com/v1")
LLM_TIMEOUT_S = int(env("AMCOP_LLM_TIMEOUT_S", "30"))
LLM_MAX_TOKENS = int(env("AMCOP_LLM_MAX_TOKENS", "700"))

# --- Analyze-endpoint hardening (optional) -----------------------------------
# An optional access token: when set, POST /analyze-operation/{id} requires an
# X-API-Token header. Empty (default) keeps the loopback dashboard working as
# before. This is NOT the provider key; it gates who may spend model calls.
ANALYST_API_TOKEN = env("AMCOP_ANALYST_API_TOKEN", "")
# Per-client in-memory rate limit (requests per window, seconds). 0 disables.
# Single-process only; resets on restart.
ANALYST_RATE_LIMIT = int(env("AMCOP_ANALYST_RATE_LIMIT", "30"))
ANALYST_RATE_WINDOW_S = int(env("AMCOP_ANALYST_RATE_WINDOW_S", "60"))


def llm_available():
    """The analyst feature requires an explicit credential."""
    return bool(LLM_API_KEY)


def get_mongo_client():
    """Single factory so app and engine agree on URI and timeouts."""
    from pymongo import MongoClient
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=1500)
