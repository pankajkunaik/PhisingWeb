import os
import io
from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from sqlalchemy.orm import Session
import datetime
import random

import sys

# Ensure the backend/app directory is in python path to resolve modules absolutely
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from database import get_db, init_db, User, ScanRecord
from services.auth import get_password_hash, verify_password, create_access_token, get_current_user, require_user
from services.scanner import analyze_url
from services.reporter import generate_pdf_report

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PhishGuard AI API", version="1.0.0", docs_url="/api/docs", redoc_url="/api/redoc")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4000",
    "http://127.0.0.1:4000",
    "*"  # Allow all for local development, restrict in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup Database Init
@app.on_event("startup")
def startup_event():
    init_db()

# Pydantic schemas
class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: str

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class ScanRequestSchema(BaseModel):
    url: str
    html_content: Optional[str] = None

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequestSchema(BaseModel):
    messages: List[ChatMessage]
    url_context: Optional[str] = None

# --- REST ENDPOINTS ---

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat()}

# 1. User Registration
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register_user(request: Request, user_data: UserRegisterSchema, db: Session = Depends(get_db)):
    # Check if user exists
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email is already registered")
        
    hashed_pwd = get_password_hash(user_data.password)
    new_user = User(email=user_data.email, password_hash=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "Registration successful", "email": new_user.email}

# 2. User Login
@app.post("/api/auth/login")
@limiter.limit("15/minute")
def login_user(request: Request, user_data: UserLoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer", "email": user.email}

# 3. Get Current User Info
@app.get("/api/auth/me")
def get_user_me(user: User = Depends(require_user)):
    return {"email": user.email, "id": user.id, "created_at": user.created_at}

# 4. Scan URL Endpoint
@app.post("/api/scan")
@limiter.limit("30/minute")
def scan_url(request: Request, scan_req: ScanRequestSchema, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_current_user)):
    url = scan_req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    # Standardize URL structure
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    try:
        # Run scanning engine
        result = analyze_url(url, scan_req.html_content)
        
        # Save record to database
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
            threat_feeds=result["threat_feeds"]
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        
        # Add the database record ID to output for PDF generation references
        result["scan_id"] = record.id
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# 5. Retrieve User Scan History
@app.get("/api/history")
def get_scan_history(db: Session = Depends(get_db), user: User = Depends(require_user)):
    records = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).order_by(ScanRecord.id.desc()).all()
    # Format database rows into matching schemas
    history = []
    for r in records:
        history.append({
            "id": r.id,
            "url": r.url,
            "risk_score": r.risk_score,
            "prediction": r.prediction,
            "created_at": r.created_at.isoformat()
        })
    return history

# 6. Live Phishing Feed (simulating global telemetry feed)
@app.get("/api/threats/feed")
def get_threats_feed():
    domains = [
        "paypal-security-auth.net", "chase-verify-login.com", "metamask-auth-seed.org",
        "binance-support-account.com", "facebook-secure-signin.net", "netflix-update-billing.org",
        "wells-fargo-active.net", "bankofamerica-login-secure.com", "steam-promo-gift.ru",
        "apple-verify-id.support"
    ]
    tlds = ["com", "net", "org", "info", "ru", "biz"]
    brands = ["PayPal", "Chase Bank", "MetaMask", "Binance", "Facebook", "Netflix", "Steam", "Apple"]
    
    # Generate 5 realistic recent threats
    feed = []
    now = datetime.datetime.utcnow()
    for i in range(5):
        feed.append({
            "domain": random.choice(domains),
            "target_brand": random.choice(brands),
            "detected_at": (now - datetime.timedelta(minutes=i * 4)).isoformat(),
            "risk_score": round(random.uniform(75.0, 100.0), 1),
            "threat_type": "Credential Harvesting" if i % 2 == 0 else "Malware Distribution"
        })
    return feed

# 7. Threat Map coordinates (simulating global attack locations)
@app.get("/api/threats/map")
def get_threats_map():
    # Coordinates of major cities/countries with mock threat weight
    locations = [
        {"city": "New York", "lat": 40.7128, "lng": -74.0060, "weight": 85},
        {"city": "London", "lat": 51.5074, "lng": -0.1278, "weight": 70},
        {"city": "Frankfurt", "lat": 50.1109, "lng": 8.6821, "weight": 65},
        {"city": "Tokyo", "lat": 35.6762, "lng": 139.6503, "weight": 90},
        {"city": "Sydney", "lat": -33.8688, "lng": 151.2093, "weight": 40},
        {"city": "Sao Paulo", "lat": -23.5505, "lng": -46.6333, "weight": 75},
        {"city": "Mumbai", "lat": 19.0760, "lng": 72.8777, "weight": 80},
        {"city": "Singapore", "lat": 1.3521, "lng": 103.8198, "weight": 50},
        {"city": "Cape Town", "lat": -33.9249, "lng": 18.4241, "weight": 45}
    ]
    return locations

# 8. PDF Report Download
@app.get("/api/report/{scan_id}")
def get_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
        
    # Recompile details dict for the PDF generator
    scan_data = {
        "url": record.url,
        "domain": record.url.replace("https://", "").replace("http://", "").split("/")[0],
        "risk_score": record.risk_score,
        "prediction": record.prediction,
        "whois_info": record.whois_info,
        "ssl_info": record.ssl_info,
        "dns_info": record.dns_info,
        "threat_feeds": record.threat_feeds,
        "reasons": []
    }
    
    # Synthesize reasons list
    if record.whois_info and record.whois_info.get("domain_age_days", 365) < 90:
        scan_data["reasons"].append(f"Domain is very young ({record.whois_info.get('domain_age_days')} days old).")
    if record.ssl_info and (not record.ssl_info.get("valid") or record.ssl_info.get("error")):
        scan_data["reasons"].append("Missing or invalid SSL/TLS certificate.")
    if record.threat_feeds and record.threat_feeds.get("flagged"):
        scan_data["reasons"].append(f"Flagged directly by: {', '.join(record.threat_feeds.get('matched_feeds', []))}")
    if record.lexical_features and record.lexical_features.get("has_login_keyword"):
        scan_data["reasons"].append("Contains phishing/credentials keywords in URL path.")
        
    if not scan_data["reasons"]:
        if record.risk_score >= 70:
            scan_data["reasons"].append("Flagged by AI model based on high correlation with known phishing lexical structures.")
        elif record.risk_score >= 30:
            scan_data["reasons"].append("Flagged as suspicious based on combined layout and structural score indicators.")
            
    try:
        pdf_bytes = generate_pdf_report(scan_data)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=PhishGuard_Report_{scan_id}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

# 9. AI Chat Security Assistant
@app.post("/api/ai/chat")
def chat_assistant(chat_req: ChatRequestSchema, db: Session = Depends(get_db)):
    messages = chat_req.messages
    url_context = chat_req.url_context
    
    if not messages:
        raise HTTPException(status_code=400, detail="No message content provided")
        
    last_user_message = next((m.content for m in reversed(messages) if m.role == "user"), "")
    
    # Check if context url is supplied and lookup latest scan
    diagnosis = None
    if url_context:
        clean_url = url_context.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url
        record = db.query(ScanRecord).filter(ScanRecord.url == clean_url).order_by(ScanRecord.id.desc()).first()
        if record:
            diagnosis = record
            
    # Compile a response based on the query structure
    query = last_user_message.lower()
    
    # General responses or context-aware explanation
    if diagnosis and ("why" in query or "flagged" in query or "phishing" in query or "safe" in query or "explain" in query):
        reasons_text = []
        if diagnosis.whois_info and diagnosis.whois_info.get("domain_age_days", 365) < 90:
            reasons_text.append(f"• Domain Age: Registered recently ({diagnosis.whois_info.get('domain_age_days')} days ago). Attackers set up domains rapidly for single campaigns.")
        if diagnosis.ssl_info and (not diagnosis.ssl_info.get("valid") or diagnosis.ssl_info.get("error")):
            reasons_text.append("• SSL/TLS Status: The connection is not secure (no valid SSL). A legitimate service handling accounts will always encrypt data.")
        if diagnosis.lexical_features and diagnosis.lexical_features.get("has_login_keyword"):
            reasons_text.append("• URL Keywords: The URL contains sensitive keywords like login/secure/verify inside the path, trying to mimic authentic portals.")
        if diagnosis.threat_feeds and diagnosis.threat_feeds.get("flagged"):
            reasons_text.append(f"• Blacklists: Direct match found in cybersecurity threat intelligence feeds ({', '.join(diagnosis.threat_feeds.get('matched_feeds', []))}).")
            
        factors_str = "\n".join(reasons_text) if reasons_text else "• AI Heuristics: Flagged due to composite lexical patterns, including multiple dots, hyphens, and redirect ratios, which match known phishing templates."
        
        reply = (
            f"Here is my analysis of **{diagnosis.url}**.\n\n"
            f"This site is currently flagged as **{diagnosis.prediction.upper()}** with a risk rating of **{diagnosis.risk_score}/100**.\n\n"
            f"Key risk triggers identified:\n{factors_str}\n\n"
            f"**Recommendation:** Do not enter any login credentials, personal information, or financial details on this site. It is highly recommended to close the tab."
        )
    elif "typosquat" in query or "similarity" in query:
        reply = (
            "Typosquatting is a social engineering technique where attackers register domains that look almost identical to famous brands (e.g., `g00gle.com` instead of `google.com`).\n\n"
            "Our engine checks the Levenshtein similarity distance of all scanned domains against a list of the top 50 global brands to flag these deceptive domains instantly."
        )
    elif "how does" in query or "work" in query or "features" in query:
        reply = (
            "PhishGuard AI analyzes websites using a multi-layered detection loop:\n"
            "1. **Lexical Analysis:** Check spelling, characters, subdomains, and keywords.\n"
            "2. **DNS & WHOIS Query:** Inspect domain registration date and active nameservers.\n"
            "3. **SSL/TLS Validation:** Analyze certificate safety and encryption ciphers.\n"
            "4. **AI Models:** Run a trained XGBoost/Random Forest model on the extracted structure.\n"
            "5. **Threat Feeds:** Cross-check with OpenPhish, PhishTank, and Google Safe Browsing."
        )
    else:
        reply = (
            "Hello! I am your PhishGuard AI security co-pilot. I can help explain scan results or answer safety questions.\n\n"
            "You can try asking:\n"
            "- *Why was the website I just scanned flagged?*\n"
            "- *What is typosquatting?*\n"
            "- *How does PhishGuard AI analyze sites?*\n"
            "- *How can I protect myself from credential harvesting?*"
        )
        
    return {"role": "assistant", "content": reply}
