"""
PhishGuard AI — Scan Router
Handles: POST /api/scan, GET /api/history, GET /api/report/{scan_id}
         GET /api/whois, GET /api/ssl, GET /api/dns
"""
import io
import os
import sys
from typing import Optional
from urllib.parse import urlparse

_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from database import get_db, User, ScanRecord
from schemas.models import ScanRequestSchema, WhoisResponse, SSLResponse, DNSResponse
from services.auth import get_current_user, get_optional_current_user, require_user
from services.scanner import analyze_url, get_whois_info, get_ssl_info, get_dns_info
from services.reporter import generate_pdf_report
from core.cache import cache_get, cache_set
from core.config import CACHE_TTL_SECONDS

router = APIRouter(prefix="/api", tags=["Scan"])


def _normalize_url(url: str) -> str:
    if not url:
        return ""
    # Strip surrounding whitespace, quotes, and angle brackets in one pass.
    # Handles pasted URLs like: ' "https://..."  ', <https://...>, etc.
    import re
    url = re.sub(r'^[\s"\'<>]+|[\s"\'<>]+$', "", url)
    # Remove markdown link syntax if user pasted [text](url)
    if "](" in url and url.endswith(")"):
        url = url.split("](")[-1][:-1].strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


# ── POST /api/scan ─────────────────────────────────────────────────────────────
@router.post("/scan")
def scan_url(
    request: Request,
    scan_req: ScanRequestSchema,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Full phishing analysis of a URL with Redis caching."""
    url = _normalize_url(scan_req.url)

    # Cache hit (only for anonymous scans without HTML content)
    cache_key = f"scan:{url}"
    if not scan_req.html_content:
        cached = cache_get(cache_key)
        if cached:
            return cached

    try:
        result = analyze_url(url, scan_req.html_content)

        record = ScanRecord(
            user_id=current_user.id if current_user else None,
            url=result["url"],
            risk_score=result["risk_score"],
            prediction=result["prediction"],
            lexical_features=result["lexical_features"],
            html_features=result["html_features"],
            whois_info=result["whois_info"],
            ssl_info=result["ssl_info"],
            dns_info=result["dns_info"],
            threat_feeds=result["threat_feeds"],
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        result["scan_id"] = record.id

        # Store in cache
        if not scan_req.html_content:
            cache_set(cache_key, result, ttl=CACHE_TTL_SECONDS)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ── GET /api/history ──────────────────────────────────────────────────────────
@router.get("/history")
def get_scan_history(
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    limit: int = 50,
    offset: int = 0,
):
    """Return the authenticated user's scan history (paginated)."""
    records = (
        db.query(ScanRecord)
        .filter(ScanRecord.user_id == user.id)
        .order_by(ScanRecord.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return [
        {
            "id": r.id,
            "url": r.url,
            "risk_score": r.risk_score,
            "prediction": r.prediction,
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]


# ── GET /api/report/{scan_id} ─────────────────────────────────────────────────
@router.get("/report/{scan_id}")
def get_pdf_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Generate and return a PDF threat intelligence report for a scan."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    # If user is authenticated, only allow access to own scans
    if current_user and record.user_id and record.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied to this report")

    scan_data = {
        "url": record.url,
        "domain": _extract_domain(record.url),
        "risk_score": record.risk_score,
        "prediction": record.prediction,
        "whois_info": record.whois_info or {},
        "ssl_info": record.ssl_info or {},
        "dns_info": record.dns_info or {},
        "threat_feeds": record.threat_feeds or {},
        "reasons": [],
    }

    # Synthesize readable reasons
    wi = record.whois_info or {}
    si = record.ssl_info or {}
    tf = record.threat_feeds or {}
    lf = record.lexical_features or {}

    if wi.get("domain_age_days", 365) < 90:
        scan_data["reasons"].append(f"Domain is very young ({wi.get('domain_age_days')} days old).")
    if not si.get("valid") or si.get("error"):
        scan_data["reasons"].append("Missing or invalid SSL/TLS certificate.")
    if tf.get("flagged"):
        scan_data["reasons"].append(f"Flagged by: {', '.join(tf.get('matched_feeds', []))}")
    if lf.get("has_login_keyword"):
        scan_data["reasons"].append("Contains phishing keywords in URL path.")
    if not scan_data["reasons"]:
        if record.risk_score >= 70:
            scan_data["reasons"].append("Flagged by AI model based on phishing lexical patterns.")
        elif record.risk_score >= 30:
            scan_data["reasons"].append("Flagged as suspicious based on structural score indicators.")

    try:
        pdf_bytes = generate_pdf_report(scan_data)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=PhishGuard_Report_{scan_id}.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


# ── GET /api/whois ────────────────────────────────────────────────────────────
@router.get("/whois")
def whois_lookup(domain: str):
    """Standalone WHOIS lookup for a domain."""
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    cache_key = f"whois:{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    info = get_whois_info(domain)
    result = {"domain": domain, **info}
    cache_set(cache_key, result, ttl=CACHE_TTL_SECONDS)
    return result


# ── GET /api/ssl ──────────────────────────────────────────────────────────────
@router.get("/ssl")
def ssl_check(domain: str):
    """Standalone SSL/TLS certificate check for a domain."""
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    cache_key = f"ssl:{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    info = get_ssl_info(domain)
    result = {"domain": domain, **info}
    cache_set(cache_key, result, ttl=1800)  # 30-min cache for SSL
    return result


# ── GET /api/dns ──────────────────────────────────────────────────────────────
@router.get("/dns")
def dns_lookup(domain: str):
    """Standalone DNS resolution for a domain."""
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    cache_key = f"dns:{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    info = get_dns_info(domain)
    result = {"domain": domain, **info}
    cache_set(cache_key, result, ttl=CACHE_TTL_SECONDS)
    return result
