"""
PhishGuard AI — AI Security Analyst Router
Powered by xAI Grok API with graceful heuristic fallback.
Handles:
- POST /api/ai/chat (Conversational cyber co-pilot)
- POST /api/ai/inspect-content (Deep phishing email/SMS/script payload inspection)
"""
import os
import sys
import json
import logging
from typing import Optional, List
import requests

_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, ScanRecord, User
from schemas.models import (
    ChatRequestSchema, 
    ChatResponse, 
    InspectContentSchema, 
    InspectContentResponse
)
from services.auth import get_current_user
from core.config import GROK_API_KEY, GROK_MODEL

logger = logging.getLogger("phishguard.ai")
router = APIRouter(prefix="/api/ai", tags=["AI Assistant"])


def _call_grok_llm(messages: List[dict], system_prompt: str) -> Optional[str]:
    """Invokes xAI Grok API (api.x.ai/v1) with chat completions."""
    if not GROK_API_KEY:
        return None

    url = "https://api.x.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROK_API_KEY}",
        "Content-Type": "application/json"
    }

    formatted_messages = [{"role": "system", "content": system_prompt}]
    for m in messages:
        formatted_messages.append({"role": m["role"], "content": m["content"]})

    payload = {
        "model": GROK_MODEL if GROK_MODEL else "grok-2-latest",
        "messages": formatted_messages,
        "temperature": 0.3,
        "max_tokens": 1000,
    }

    try:
        res = requests.post(url, headers=headers, json=payload, timeout=12.0)
        if res.status_code == 200:
            data = res.json()
            return data["choices"][0]["message"]["content"]
        else:
            logger.warning("Grok API non-200 (%s): %s", res.status_code, res.text)
    except Exception as e:
        logger.warning("Grok API call failed: %s", e)

    return None


@router.post("/chat", response_model=ChatResponse)
def chat_assistant(
    chat_req: ChatRequestSchema, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Phishing security AI assistant powered by Grok API / Heuristic reasoning.
    Provides contextual explanations about scan results, threat intelligence, and defense steps.
    """
    if not chat_req.messages:
        raise HTTPException(status_code=400, detail="No message content provided")

    last_user_message = next(
        (m.content for m in reversed(chat_req.messages) if m.role == "user"), ""
    )

    # Look up most recent scan context URL if provided
    diagnosis = None
    if chat_req.url_context:
        clean_url = chat_req.url_context.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url
        diagnosis = (
            db.query(ScanRecord)
            .filter(ScanRecord.url == clean_url)
            .order_by(ScanRecord.id.desc())
            .first()
        )

    # 1. Attempt Grok API generation
    if GROK_API_KEY:
        system_context = (
            "You are PhishGuard AI Cyber Analyst, powered by Grok. You are an expert in phishing detection, "
            "credential theft analysis, social engineering, SSL/TLS validation, typosquatting, and DNS intelligence.\n"
            "Provide concise, authoritative, professional, and actionable cybersecurity advice.\n"
            "Format your responses using clean Markdown with bullet points where appropriate."
        )
        if diagnosis:
            system_context += (
                f"\n\n[CURRENT SCAN CONTEXT]\n"
                f"- Target URL: {diagnosis.url}\n"
                f"- Classification: {diagnosis.prediction} (Risk Score: {diagnosis.risk_score}/100)\n"
                f"- WHOIS Details: {json.dumps(diagnosis.whois_info or {})}\n"
                f"- SSL Status: {json.dumps(diagnosis.ssl_info or {})}\n"
                f"- DNS Records: {json.dumps(diagnosis.dns_info or {})}\n"
                f"- Matched Threat Feeds: {json.dumps(diagnosis.threat_feeds or {})}\n"
                f"- Lexical Indicators: {json.dumps(diagnosis.lexical_features or {})}"
            )

        grok_reply = _call_grok_llm(
            [{"role": m.role, "content": m.content} for m in chat_req.messages],
            system_context
        )
        if grok_reply:
            return ChatResponse(role="assistant", content=grok_reply)

    # 2. Rule-based Heuristic Fallback Engine
    query = last_user_message.lower()

    if diagnosis and any(kw in query for kw in ["why", "flagged", "phishing", "safe", "explain", "reason", "score"]):
        reasons = []
        wi = diagnosis.whois_info or {}
        si = diagnosis.ssl_info or {}
        lf = diagnosis.lexical_features or {}
        tf = diagnosis.threat_feeds or {}

        if wi.get("domain_age_days", 365) < 90:
            reasons.append(
                f"• **Domain Age:** Registered only {wi.get('domain_age_days')} days ago. "
                "Attackers frequently register new domains for disposable phishing campaigns."
            )
        if not si.get("valid") or si.get("error"):
            reasons.append(
                "• **SSL/TLS Status:** The connection is not encrypted or uses an invalid certificate."
            )
        if lf.get("has_login_keyword"):
            reasons.append(
                "• **URL Path Keywords:** Contains deceptive keywords like `login`, `verify`, or `secure`."
            )
        if tf.get("flagged"):
            feeds = ", ".join(tf.get("matched_feeds", []))
            reasons.append(f"• **Threat Feeds:** Actively listed on threat databases ({feeds}).")

        if not reasons:
            reasons.append(
                "• **Heuristic Pattern:** Flagged by AI model based on lexical structure and domain characteristics."
            )

        factors = "\n".join(reasons)
        reply = (
            f"### PhishGuard Threat Breakdown for `{diagnosis.url}`\n\n"
            f"**Classification:** `{diagnosis.prediction.upper()}` | **Risk Score:** `{diagnosis.risk_score}/100`\n\n"
            f"**Key Findings:**\n{factors}\n\n"
            f"**Security Guidance:** Do not enter passwords, OTPs, or financial credentials on this domain."
        )

    elif any(kw in query for kw in ["typosquat", "similarity", "impersonat", "fake domain"]):
        reply = (
            "**Typosquatting** is a deceptive attack where malicious actors register domains resembling legitimate brands.\n\n"
            "**Common Typo Techniques:**\n"
            "• **Character Substitution:** `paypa1.com` instead of `paypal.com`\n"
            "• **Affixation:** `security-netflix.com`\n"
            "• **Combosquatting:** `bankofamerica-login.net`\n\n"
            "PhishGuard AI uses Levenshtein sequence matching to detect brand impersonation before users enter credentials."
        )

    elif any(kw in query for kw in ["protect", "safe", "tip", "advice", "credential", "mfa", "2fa"]):
        reply = (
            "**Recommended Defensive Measures:**\n\n"
            "1. **Check Domain Roots:** Always inspect the top-level domain before logging in.\n"
            "2. **Use Hardware 2FA / Passkeys:** FIDO2/WebAuthn keys cannot be intercepted by phishing proxies.\n"
            "3. **Password Managers:** Never fill credentials automatically on unverified domains.\n"
            "4. **Continuous Monitoring:** Add your company's critical domains to your PhishGuard Monitored Watchlist."
        )

    else:
        reply = (
            "Hello! I am your **PhishGuard AI Security Co-pilot** 🛡️\n\n"
            "I can explain threat indicators, verify suspicious domains, analyze payload snippets, and guide your security posture.\n\n"
            "**Try asking:**\n"
            "- *Why was the domain I scanned given this threat score?*\n"
            "- *How do attackers use typosquatting to harvest credentials?*\n"
            "- *What are best practices for securing corporate domains?*"
        )

    return ChatResponse(role="assistant", content=reply)


@router.post("/inspect-content", response_model=InspectContentResponse)
def inspect_content(
    payload: InspectContentSchema,
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Analyzes suspicious email text, SMS messages, or HTML script payloads for phishing markers.
    Utilizes Grok API or advanced heuristic pattern parsing.
    """
    raw_content = payload.content.strip()
    if not raw_content:
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    # 1. Attempt Grok API Inspection
    if GROK_API_KEY:
        system_prompt = (
            "You are a Senior Cyber Threat Intelligence Analyst. You will analyze suspicious text, email, or HTML code.\n"
            "Return a strictly valid JSON response with this exact structure:\n"
            "{\n"
            '  "analysis": "detailed markdown explanation",\n'
            '  "risk_level": "Safe" or "Suspicious" or "Phishing / Malicious",\n'
            '  "indicators": ["indicator 1", "indicator 2"],\n'
            '  "recommendation": "clear actionable advice"\n'
            "}\n"
            "Do not wrap in backticks or markdown fences if possible."
        )
        user_msg = f"Analyze the following {payload.content_type} snippet:\n\n{raw_content[:4000]}"
        grok_out = _call_grok_llm([{"role": "user", "content": user_msg}], system_prompt)
        if grok_out:
            try:
                clean_json = grok_out.strip()
                if clean_json.startswith("```json"):
                    clean_json = clean_json[7:]
                if clean_json.startswith("```"):
                    clean_json = clean_json[3:]
                if clean_json.endswith("```"):
                    clean_json = clean_json[:-3]
                parsed = json.loads(clean_json.strip())
                return InspectContentResponse(
                    analysis=parsed.get("analysis", "Grok analysis completed."),
                    risk_level=parsed.get("risk_level", "Suspicious"),
                    indicators=parsed.get("indicators", ["Content evaluated by Grok LLM"]),
                    recommendation=parsed.get("recommendation", "Exercise caution when interacting with unknown content.")
                )
            except Exception:
                pass

    # 2. Heuristic Rule-Based Content Analyzer
    content_lower = raw_content.lower()
    indicators = []
    urgency_keywords = ["urgent", "suspended", "immediately", "verify your account", "unauthorized access", "action required", "24 hours"]
    cred_keywords = ["password", "ssn", "seed phrase", "credit card", "billing update", "login here", "click link"]
    html_markers = ["<script", "eval(", "unescape(", "document.location", "iframe", "type=\"password\""]

    for kw in urgency_keywords:
        if kw in content_lower:
            indicators.append(f"Urgency / Coercion Keyword Detected: '{kw}'")

    for kw in cred_keywords:
        if kw in content_lower:
            indicators.append(f"Credential / Sensitive Data Prompt: '{kw}'")

    for hm in html_markers:
        if hm in content_lower:
            indicators.append(f"Suspicious Web/Script Element: '{hm}'")

    risk_level = "Safe"
    if len(indicators) >= 3:
        risk_level = "Phishing / Malicious"
    elif len(indicators) >= 1:
        risk_level = "Suspicious"

    analysis = (
        f"Evaluated {len(raw_content)} characters of {payload.content_type}. "
        f"Identified {len(indicators)} risk marker(s) typical of social engineering and credential theft campaigns."
    )
    recommendation = (
        "Do not click embedded links, download attachments, or input passwords. "
        "Report the communication to your security team."
        if risk_level != "Safe"
        else "No obvious social engineering patterns detected. Ensure standard verification practices."
    )

    return InspectContentResponse(
        analysis=analysis,
        risk_level=risk_level,
        indicators=indicators if indicators else ["No explicit malicious keywords identified"],
        recommendation=recommendation
    )
