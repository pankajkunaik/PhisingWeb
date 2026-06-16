"""Quick API integration test script."""
import requests, json, sys

BASE = "http://127.0.0.1:8000"

import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

def test_health():
    r = requests.get(f"{BASE}/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "healthy"
    print("✓ Health check passed")

def test_register_and_login():
    # Register
    r = requests.post(f"{BASE}/api/auth/register", json={"email": "test@phishguard.dev", "password": "SecurePass123!"})
    if r.status_code == 201:
        print("✓ Registration passed")
    elif r.status_code == 400 and "already registered" in r.text:
        print("✓ Registration skipped (already exists)")
    else:
        print(f"✗ Registration FAILED: {r.status_code} {r.text}")
        return None

    # Login
    r = requests.post(f"{BASE}/api/auth/login", json={"email": "test@phishguard.dev", "password": "SecurePass123!"})
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json()["access_token"]
    print(f"✓ Login passed (token: {token[:20]}...)")
    return token

def test_scan(token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    r = requests.post(f"{BASE}/api/scan", json={"url": "paypal-security-update.com"}, headers=headers)
    assert r.status_code == 200, f"Scan failed: {r.status_code} {r.text}"
    data = r.json()
    print(f"✓ Scan passed → Prediction: {data['prediction']}, Risk Score: {data['risk_score']}")
    print(f"  Domain: {data['domain']}")
    print(f"  Reasons: {data['reasons'][:2]}")
    return data.get("scan_id")

def test_history(token):
    r = requests.get(f"{BASE}/api/history", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, f"History failed: {r.status_code} {r.text}"
    data = r.json()
    print(f"✓ History passed → {len(data)} records found")

def test_threats_feed():
    r = requests.get(f"{BASE}/api/threats/feed")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 5
    print(f"✓ Threats feed passed → {len(data)} threat items")

def test_threats_map():
    r = requests.get(f"{BASE}/api/threats/map")
    assert r.status_code == 200
    data = r.json()
    assert len(data) > 0
    print(f"✓ Threats map passed → {len(data)} locations")

def test_chat():
    r = requests.post(f"{BASE}/api/ai/chat", json={
        "messages": [{"role": "user", "content": "How does PhishGuard AI work?"}],
        "url_context": None
    })
    assert r.status_code == 200, f"Chat failed: {r.text}"
    data = r.json()
    print(f"✓ AI Chat passed → Response length: {len(data['content'])} chars")

def test_pdf(scan_id):
    if not scan_id:
        print("⊘ PDF test skipped (no scan_id)")
        return
    r = requests.get(f"{BASE}/api/report/{scan_id}")
    assert r.status_code == 200, f"PDF failed: {r.status_code} {r.text}"
    assert r.headers.get("content-type") == "application/pdf"
    print(f"✓ PDF Report passed → {len(r.content)} bytes")

if __name__ == "__main__":
    print("=" * 50)
    print("PhishGuard AI - API Integration Test Suite")
    print("=" * 50)
    
    try:
        test_health()
        token = test_register_and_login()
        scan_id = test_scan(token)
        if token:
            test_history(token)
        test_threats_feed()
        test_threats_map()
        test_chat()
        test_pdf(scan_id)
        
        print("\n" + "=" * 50)
        print("ALL TESTS PASSED ✓")
        print("=" * 50)
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        sys.exit(1)
