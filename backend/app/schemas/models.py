"""
PhishGuard AI — Pydantic Request/Response Schemas
"""
from pydantic import BaseModel, EmailStr, field_validator
from typing import List, Optional, Dict, Any


# ── Auth ──────────────────────────────────────────────────────────────────────
class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    email: str


class UserMeResponse(BaseModel):
    id: int
    email: str
    created_at: Any  # datetime serialized as string


# ── Scan ──────────────────────────────────────────────────────────────────────
class ScanRequestSchema(BaseModel):
    url: str
    html_content: Optional[str] = None

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        return v


class XAIExplanation(BaseModel):
    factor: str
    severity: str  # "high" | "medium" | "low"


class ScanResponse(BaseModel):
    scan_id: Optional[int] = None
    url: str
    domain: str
    risk_score: float
    prediction: str  # "Safe" | "Suspicious" | "Phishing"
    reasons: List[str]
    xai_explanations: List[XAIExplanation]
    lexical_features: Dict[str, Any]
    html_features: Dict[str, Any]
    whois_info: Dict[str, Any]
    ssl_info: Dict[str, Any]
    dns_info: Dict[str, Any]
    threat_feeds: Dict[str, Any]


class HistoryItem(BaseModel):
    id: int
    url: str
    risk_score: float
    prediction: str
    created_at: str


# ── AI Chat ───────────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequestSchema(BaseModel):
    messages: List[ChatMessage]
    url_context: Optional[str] = None


class ChatResponse(BaseModel):
    role: str
    content: str


# ── Threat Intel ──────────────────────────────────────────────────────────────
class ThreatFeedItem(BaseModel):
    domain: str
    target_brand: str
    detected_at: str
    risk_score: float
    threat_type: str


class ThreatMapPoint(BaseModel):
    city: str
    lat: float
    lng: float
    weight: int


# ── Stats ─────────────────────────────────────────────────────────────────────
class StatsResponse(BaseModel):
    total_scans: int
    total_phishing_detected: int
    total_safe: int
    total_suspicious: int
    detection_accuracy: float
    active_users: int


# ── Domain Checks ─────────────────────────────────────────────────────────────
class WhoisResponse(BaseModel):
    domain: str
    domain_age_days: int
    registrar: str
    creation_date: str
    expiration_date: str
    country: str


class SSLResponse(BaseModel):
    domain: str
    valid: bool
    issuer: str
    expiration_date: str
    cipher: str
    error: Optional[str] = None


class DNSResponse(BaseModel):
    domain: str
    ips: List[str]
    mx_servers: List[str]
    ns_servers: List[str]
    hosting_provider: str


# ── Watchlist & User Hub ──────────────────────────────────────────────────────
class WatchlistCreateSchema(BaseModel):
    domain: str
    label: Optional[str] = None


class WatchlistResponse(BaseModel):
    id: int
    domain: str
    label: Optional[str] = None
    status: str
    ssl_valid: int
    ssl_days_left: int
    risk_score: float
    last_checked: str
    created_at: str


class UserStatsResponse(BaseModel):
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    phishing_scans: int
    threat_rate: float
    security_grade: str
    watchlist_count: int
    member_since: str


# ── Grok Deep Content Inspector ───────────────────────────────────────────────
class InspectContentSchema(BaseModel):
    content: str
    content_type: Optional[str] = "email_or_text"  # email_or_text, html_script, url_snippet


class InspectContentResponse(BaseModel):
    analysis: str
    risk_level: str  # Safe, Suspicious, Phishing / Malicious
    indicators: List[str]
    recommendation: str
