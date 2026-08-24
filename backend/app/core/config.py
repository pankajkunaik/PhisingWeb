"""
PhishGuard AI — Core Configuration
Loads all settings from environment variables / .env file.
"""
import os
from typing import List
from dotenv import load_dotenv

# Load .env file if it exists (dev convenience)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../../.env"))

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY: str = os.getenv(
    "SECRET_KEY",
    "phishguard_dev_secret_key_change_in_production_abc123xyz"
)
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24h

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

# ── Redis caching (optional) ──────────────────────────────────────────────────
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", "3600"))  # 1 hour

# ── CORS ──────────────────────────────────────────────────────────────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:4000")
ALLOWED_ORIGINS: List[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ── Threat Intel & AI API Keys ────────────────────────────────────────────────
GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
PHISHTANK_APP_KEY: str = os.getenv("PHISHTANK_APP_KEY", "")
GROK_API_KEY: str = os.getenv("GROK_API_KEY", os.getenv("XAI_API_KEY", ""))
GROK_MODEL: str = os.getenv("GROK_MODEL", "grok-2-latest")

# ── Application ───────────────────────────────────────────────────────────────
APP_ENV: str = os.getenv("APP_ENV", "development")
IS_PRODUCTION: bool = APP_ENV == "production"

# ── ML model paths (resolved to absolute at startup) ─────────────────────────
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
ML_MODEL_JSON: str = os.path.join(_root, "ml", "models", "phishguard_model.json")
ML_MODEL_PKL: str = os.path.join(_root, "ml", "models", "phishguard_model.pkl")
