"""
PhishGuard AI — Redis Cache Helper
Provides a lightweight caching wrapper that degrades gracefully
when Redis is unavailable (falls back to no-cache mode).
"""
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

import time

_redis_client = None
_last_check_time = 0
_REDIS_RETRY_INTERVAL = 60  # Retry connecting every 60s if offline


def get_redis():
    """Returns a connected Redis client, or None if unavailable."""
    global _redis_client, _last_check_time
    if _redis_client is not None:
        return _redis_client
    
    # Avoid reconnecting repeatedly if Redis is down
    now = time.time()
    if now - _last_check_time < _REDIS_RETRY_INTERVAL:
        return None
    
    _last_check_time = now
    try:
        import redis
        from core.config import REDIS_URL
        client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=0.5)
        client.ping()
        _redis_client = client
        logger.info("✅ Redis connected: %s", REDIS_URL)
        return _redis_client
    except Exception as e:
        logger.warning("⚠️  Redis unavailable (%s) — running in-memory/direct mode", e)
        return None


def cache_get(key: str) -> Optional[Any]:
    """Retrieve a cached JSON value. Returns None on miss or error."""
    client = get_redis()
    if not client:
        return None
    try:
        raw = client.get(key)
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.debug("Cache GET error: %s", e)
    return None


def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    """Store a JSON-serialisable value in cache with TTL (seconds)."""
    client = get_redis()
    if not client:
        return
    try:
        client.setex(key, ttl, json.dumps(value, default=str))
    except Exception as e:
        logger.debug("Cache SET error: %s", e)


def cache_delete(key: str) -> None:
    """Delete a key from cache."""
    client = get_redis()
    if not client:
        return
    try:
        client.delete(key)
    except Exception as e:
        logger.debug("Cache DELETE error: %s", e)
