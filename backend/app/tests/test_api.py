"""
PhishGuard AI — API Integration Tests
Run with: pytest app/tests/ -v
"""
import os
import sys
import importlib

pytest = None
try:
    pytest = importlib.import_module("pytest")
except ImportError:
    pass

# Ensure app directory is on the path
_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_root_dir = os.path.abspath(os.path.join(_app_dir, "../../"))
for _p in [_app_dir, _root_dir]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_phishguard.db")
os.environ.setdefault("SECRET_KEY", "test_secret_key_for_testing_only_long")
os.environ.setdefault("APP_ENV", "development")

from fastapi.testclient import TestClient
from main import app
from database import init_db

# Initialize database
init_db()

client = TestClient(app, raise_server_exceptions=False)

if pytest is not None:
    @pytest.fixture(scope="session", autouse=True)
    def setup_db():
        """Ensure the test database is initialised once for the full session."""
        init_db()
        yield
        # Cleanup
        if os.path.exists("test_phishguard.db"):
            try:
                os.remove("test_phishguard.db")
            except PermissionError:
                pass


# ── Health ─────────────────────────────────────────────────────────────────────
def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "timestamp" in data


# ── Auth ───────────────────────────────────────────────────────────────────────
def test_register_and_login():
    # Register
    res = client.post("/api/auth/register", json={
        "email": "test@phishguard.ai",
        "password": "securePass123"
    })
    assert res.status_code in (201, 400)  # 400 if already exists

    # Login
    res = client.post("/api/auth/login", json={
        "email": "test@phishguard.ai",
        "password": "securePass123"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    return data["access_token"]


def test_login_invalid_password():
    res = client.post("/api/auth/login", json={
        "email": "test@phishguard.ai",
        "password": "wrongpassword"
    })
    assert res.status_code == 401


def test_register_weak_password():
    res = client.post("/api/auth/register", json={
        "email": "weakpass@test.com",
        "password": "short"
    })
    assert res.status_code == 422  # Pydantic validation error


# ── Scan ───────────────────────────────────────────────────────────────────────
def test_scan_safe_url():
    res = client.post("/api/scan", json={"url": "https://google.com"})
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "prediction" in data
    assert data["prediction"] in ("Safe", "Suspicious", "Phishing")
    assert 0 <= data["risk_score"] <= 100


def test_scan_phishing_url():
    res = client.post("/api/scan", json={"url": "http://paypal-security-update.com/login/verify"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] > 30  # Should be at least suspicious


def test_scan_empty_url():
    res = client.post("/api/scan", json={"url": ""})
    assert res.status_code == 422


def test_scan_url_no_scheme():
    res = client.post("/api/scan", json={"url": "example.com"})
    assert res.status_code == 200  # Should auto-add https://


# ── Threat API ─────────────────────────────────────────────────────────────────
def test_threats_feed():
    res = client.get("/api/threats/feed")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    if data:
        assert "domain" in data[0]
        assert "risk_score" in data[0]


def test_threats_map():
    res = client.get("/api/threats/map")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "lat" in data[0]
    assert "lng" in data[0]


def test_stats_endpoint():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_scans" in data
    assert "detection_accuracy" in data


# ── Domain Checks ──────────────────────────────────────────────────────────────
def test_whois_endpoint():
    res = client.get("/api/whois?domain=google.com")
    assert res.status_code == 200
    data = res.json()
    assert "domain" in data
    assert "domain_age_days" in data


def test_ssl_endpoint():
    res = client.get("/api/ssl?domain=google.com")
    assert res.status_code == 200
    data = res.json()
    assert "domain" in data
    assert "valid" in data


def test_dns_endpoint():
    res = client.get("/api/dns?domain=google.com")
    assert res.status_code == 200
    data = res.json()
    assert "domain" in data
    assert "ips" in data


def test_whois_missing_param():
    res = client.get("/api/whois")
    assert res.status_code == 422


# ── AI Chat ────────────────────────────────────────────────────────────────────
def test_ai_chat_default_response():
    res = client.post("/api/ai/chat", json={
        "messages": [{"role": "user", "content": "Hello!"}]
    })
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "assistant"
    assert len(data["content"]) > 0


def test_ai_chat_how_does_it_work():
    res = client.post("/api/ai/chat", json={
        "messages": [{"role": "user", "content": "How does PhishGuard work?"}]
    })
    assert res.status_code == 200
    data = res.json()
    assert "layer" in data["content"].lower() or "detect" in data["content"].lower() or "phishguard" in data["content"].lower() or "threat" in data["content"].lower()


def test_ai_chat_empty_messages():
    res = client.post("/api/ai/chat", json={"messages": []})
    assert res.status_code == 400


# ── History (auth-required) ────────────────────────────────────────────────────
def test_history_requires_auth():
    res = client.get("/api/history")
    assert res.status_code == 401


def test_me_requires_auth():
    res = client.get("/api/auth/me")
    assert res.status_code == 401


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("=" * 60)
    print("Running PhishGuard AI Backend Unit Test Suite (TestClient)")
    print("=" * 60)
    passed = 0
    failed = 0
    test_funcs = [
        test_health_check,
        test_register_and_login,
        test_login_invalid_password,
        test_register_weak_password,
        test_scan_safe_url,
        test_scan_phishing_url,
        test_scan_empty_url,
        test_scan_url_no_scheme,
        test_threats_feed,
        test_threats_map,
        test_stats_endpoint,
        test_whois_endpoint,
        test_ssl_endpoint,
        test_dns_endpoint,
        test_whois_missing_param,
        test_ai_chat_default_response,
        test_ai_chat_how_does_it_work,
        test_ai_chat_empty_messages,
        test_history_requires_auth,
        test_me_requires_auth,
    ]
    for fn in test_funcs:
        try:
            fn()
            print(f"  [PASS] {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {fn.__name__}: {e}")
            failed += 1
    print("=" * 60)
    print(f"Total: {len(test_funcs)} | Passed: {passed} | Failed: {failed}")
    print("=" * 60)
    if failed > 0:
        sys.exit(1)
