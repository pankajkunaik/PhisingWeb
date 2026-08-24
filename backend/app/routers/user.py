"""
PhishGuard AI — User Security Hub Router
Handles:
- GET /api/user/stats (Aggregated threat analytics from Neon DB)
- GET /api/user/watchlist (Monitored domain watchlist)
- POST /api/user/watchlist (Add domain to monitor)
- DELETE /api/user/watchlist/{id} (Remove domain from monitor)
- DELETE /api/user/history/{scan_id} (Delete scan record from history)
"""
import os
import sys
from datetime import datetime
from typing import List
from urllib.parse import urlparse

_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db, User, ScanRecord, WatchlistDomain
from schemas.models import (
    UserStatsResponse, 
    WatchlistCreateSchema, 
    WatchlistResponse
)
from services.auth import require_user
from services.scanner import get_ssl_info, check_threat_feeds, check_typosquatting

router = APIRouter(prefix="/api/user", tags=["User Hub"])


def _clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        try:
            return urlparse(raw).netloc
        except Exception:
            pass
    if raw.startswith("www."):
        raw = raw[4:]
    return raw.split("/")[0]


@router.get("/stats", response_model=UserStatsResponse)
def get_user_statistics(
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Computes real personal cybersecurity telemetry from Neon PostgreSQL."""
    scans = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).all()
    watchlist_count = db.query(WatchlistDomain).filter(WatchlistDomain.user_id == user.id).count()

    total = len(scans)
    safe = sum(1 for s in scans if s.prediction == "Safe")
    suspicious = sum(1 for s in scans if s.prediction == "Suspicious")
    phishing = sum(1 for s in scans if s.prediction == "Phishing")

    threat_rate = round(((phishing + suspicious) / total * 100), 1) if total > 0 else 0.0

    # Calculate Security Grade based on threat encounters and awareness
    if total == 0:
        grade = "N/A"
    elif phishing == 0 and suspicious == 0:
        grade = "A+"
    elif phishing == 0 and suspicious <= 2:
        grade = "A"
    elif phishing <= 2:
        grade = "B"
    elif phishing <= 5:
        grade = "C"
    else:
        grade = "Needs Attention"

    member_since = user.created_at.strftime("%B %Y") if user.created_at else "Recently"

    return UserStatsResponse(
        total_scans=total,
        safe_scans=safe,
        suspicious_scans=suspicious,
        phishing_scans=phishing,
        threat_rate=threat_rate,
        security_grade=grade,
        watchlist_count=watchlist_count,
        member_since=member_since
    )


@router.get("/watchlist", response_model=List[WatchlistResponse])
def get_watchlist(
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Retrieves user's monitored domain watchlist."""
    items = (
        db.query(WatchlistDomain)
        .filter(WatchlistDomain.user_id == user.id)
        .order_by(WatchlistDomain.id.desc())
        .all()
    )
    return [
        WatchlistResponse(
            id=item.id,
            domain=item.domain,
            label=item.label,
            status=item.status,
            ssl_valid=item.ssl_valid,
            ssl_days_left=item.ssl_days_left,
            risk_score=item.risk_score,
            last_checked=item.last_checked.isoformat(),
            created_at=item.created_at.isoformat()
        )
        for item in items
    ]


@router.post("/watchlist", response_model=WatchlistResponse, status_code=status.HTTP_201_CREATED)
def add_to_watchlist(
    data: WatchlistCreateSchema,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Adds a new domain to the user's monitored watchlist and runs real diagnostics."""
    domain = _clean_domain(data.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain name provided")

    # Check for duplicate in user's watchlist
    existing = (
        db.query(WatchlistDomain)
        .filter(WatchlistDomain.user_id == user.id, WatchlistDomain.domain == domain)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail=f"'{domain}' is already in your watchlist")

    # Run initial live diagnostics on the domain
    ssl_info = get_ssl_info(domain)
    threat_info = check_threat_feeds(domain)
    typosquat = check_typosquatting(domain)

    ssl_valid = 1 if ssl_info.get("valid") else 0
    ssl_days_left = 365
    exp_date_str = ssl_info.get("expiration_date", "")
    if exp_date_str and exp_date_str != "None":
        try:
            exp_date = datetime.fromisoformat(exp_date_str)
            ssl_days_left = max(0, (exp_date - datetime.utcnow()).days)
        except Exception:
            ssl_days_left = 180

    risk_score = 0.0
    status_label = "Active"

    if threat_info.get("flagged"):
        risk_score = 100.0
        status_label = "Critical"
    elif not ssl_valid or ssl_days_left < 15 or typosquat.get("is_typosquat"):
        risk_score = 45.0
        status_label = "Warning"

    new_item = WatchlistDomain(
        user_id=user.id,
        domain=domain,
        label=data.label or "Primary Asset",
        status=status_label,
        ssl_valid=ssl_valid,
        ssl_days_left=ssl_days_left,
        risk_score=risk_score,
        last_checked=datetime.utcnow()
    )
    db.add(new_item)
    db.commit()
    db.refresh(new_item)

    return WatchlistResponse(
        id=new_item.id,
        domain=new_item.domain,
        label=new_item.label,
        status=new_item.status,
        ssl_valid=new_item.ssl_valid,
        ssl_days_left=new_item.ssl_days_left,
        risk_score=new_item.risk_score,
        last_checked=new_item.last_checked.isoformat(),
        created_at=new_item.created_at.isoformat()
    )


@router.delete("/watchlist/{item_id}", status_code=status.HTTP_200_OK)
def delete_from_watchlist(
    item_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Removes a domain from the user's watchlist."""
    item = (
        db.query(WatchlistDomain)
        .filter(WatchlistDomain.id == item_id, WatchlistDomain.user_id == user.id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Watchlist domain not found")

    db.delete(item)
    db.commit()
    return {"message": "Domain removed from watchlist", "id": item_id}


@router.delete("/history/{scan_id}", status_code=status.HTTP_200_OK)
def delete_scan_record(
    scan_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Deletes a personal scan record from history."""
    scan = (
        db.query(ScanRecord)
        .filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    db.delete(scan)
    db.commit()
    return {"message": "Scan record deleted", "scan_id": scan_id}
