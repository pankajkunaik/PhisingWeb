"""
PhishGuard AI — FastAPI Application Entry Point
Assembles all routers and middleware.
"""
import os
import sys
import logging
from contextlib import asynccontextmanager

import datetime

# ── Path bootstrap (must be before local imports) ─────────────────────────────
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, "../../"))
for _p in [current_dir, root_dir]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from core.config import ALLOWED_ORIGINS, IS_PRODUCTION
from database import init_db

# Import routers
from routers.auth import router as auth_router
from routers.scan import router as scan_router
from routers.threats import router as threats_router
from routers.ai_chat import router as ai_chat_router
from routers.user import router as user_router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
)
logger = logging.getLogger("phishguard")

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Lifespan (replaces deprecated @app.on_event) ─────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 PhishGuard AI backend starting…")
    init_db()
    logger.info("✅ Database initialised")
    yield
    logger.info("🛑 PhishGuard AI backend shutting down")


# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard AI API",
    version="2.0.0",
    description="AI-powered phishing detection & threat intelligence platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS (env-driven, regex support for local dev ports) ──────────────────────
if IS_PRODUCTION:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:[0-9]+)?",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(threats_router)
app.include_router(ai_chat_router)
app.include_router(user_router)


# ── Root & Health Check ────────────────────────────────────────────────────────
@app.get("/", tags=["Root"])
def root():
    return {
        "name": "PhishGuard AI Backend API",
        "status": "online",
        "version": "2.0.0",
        "docs": "/api/docs",
        "health": "/api/health",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "environment": "production" if IS_PRODUCTION else "development",
    }


@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "environment": "production" if IS_PRODUCTION else "development",
    }


# ── Dev runner ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
