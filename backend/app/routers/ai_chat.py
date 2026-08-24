"""
PhishGuard AI — AI Security Analyst Router
Powered by xAI Grok API with structured output processing and graceful heuristic fallback.
Handles:
- POST /api/ai/chat (Conversational cyber co-pilot)
- POST /api/ai/inspect-content (Deep phishing email/SMS/script payload inspection)
"""
import os
import sys
import re
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


def _clean_markdown_response(text: str) -> str:
    """Cleans up raw LLM markdown output to ensure crisp formatting."""
    if not text:
        return ""
    cleaned = text.strip()
    # Strip <think>...</think> reasoning blocks produced by deepseek/qwen/reasoning models
    cleaned = re.sub(r'<think>.*?</think>', '', cleaned, flags=re.DOTALL).strip()
    # Strip unnecessary code block fences around full text
    if cleaned.startswith("```markdown"):
        cleaned = cleaned[11:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    return cleaned.strip()


def _call_grok_llm(messages: List[dict], system_prompt: str) -> Optional[str]:
    """Invokes Groq (api.groq.com) or xAI Grok (api.x.ai) chat completions."""
    if not GROK_API_KEY:
        return None

    raw_key = GROK_API_KEY.strip()
    is_groq = raw_key.startswith("gsk_")

    if is_groq:
        url = "https://api.groq.com/openai/v1/chat/completions"
        models_to_try = [
            GROK_MODEL if GROK_MODEL and GROK_MODEL != "grok-2-latest" else "qwen/qwen3.6-27b",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "groq/compound",
        ]
    else:
        url = "https://api.x.ai/v1/chat/completions"
        models_to_try = [GROK_MODEL if GROK_MODEL else "grok-2-latest", "grok-beta"]

    headers = {
        "Authorization": f"Bearer {raw_key}",
        "Content-Type": "application/json"
    }

    formatted_messages = [{"role": "system", "content": system_prompt}]
    for m in messages:
        formatted_messages.append({"role": m["role"], "content": m["content"]})

    for model_name in dict.fromkeys(models_to_try):
        payload = {
            "model": model_name,
            "messages": formatted_messages,
            "temperature": 0.2,
            "max_tokens": 1000,
        }

        try:
            res = requests.post(url, headers=headers, json=payload, timeout=10.0)
            if res.status_code == 200:
                data = res.json()
                raw_content = data["choices"][0]["message"]["content"]
                return _clean_markdown_response(raw_content)
            else:
                logger.warning("LLM API non-200 (%s) on model %s: %s", res.status_code, model_name, res.text)
        except Exception as e:
            logger.warning("LLM API call failed on model %s: %s", model_name, e)

    return None


@router.post("/chat", response_model=ChatResponse)
def chat_assistant(
    chat_req: ChatRequestSchema, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Phishing security AI assistant powered by xAI Grok API with structured heuristic fallback.
    Provides clean, accurate, contextual explanations about scan results, threat intelligence, and defense steps.
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

    # 1. Attempt Grok API generation with rich security context
    if GROK_API_KEY:
        system_context = (
            "You are PhishGuard AI Cyber Analyst, powered by Grok. You are a world-class cybersecurity specialist in "
            "phishing detection, credential theft, social engineering, SSL/TLS validation, typosquatting, and DNS intelligence.\n\n"
            "Guidelines for response:\n"
            "1. Be authoritative, concise, accurate, and actionable.\n"
            "2. Structure your reply with clean Markdown headers, bullet points, and bold keywords.\n"
            "3. Ground your explanation in the provided scan telemetry data. Do not hallucinate false findings.\n"
            "4. Provide a concrete 'Actionable Defense Guidance' section at the end of your evaluation."
        )
        
        if diagnosis:
            wi = diagnosis.whois_info or {}
            si = diagnosis.ssl_info or {}
            di = diagnosis.dns_info or {}
            tf = diagnosis.threat_feeds or {}
            lf = diagnosis.lexical_features or {}

            system_context += (
                f"\n\n[CURRENT LIVE SCAN TELEMETRY]\n"
                f"- Target URL: {diagnosis.url}\n"
                f"- Threat Verdict: {diagnosis.prediction} (Risk Score: {diagnosis.risk_score}/100)\n"
                f"- WHOIS Domain Age: {wi.get('domain_age_days', 'Unknown')} days | Registrar: {wi.get('registrar', 'Unknown')} | Country: {wi.get('country', 'Unknown')}\n"
                f"- SSL Status: {'Valid' if si.get('valid') else 'Invalid/Insecure'} | Issuer: {si.get('issuer', 'None')} | Cipher: {si.get('cipher', 'None')}\n"
                f"- DNS Resolved IPs: {', '.join(di.get('ips', [])) if di.get('ips') else 'None'} | Host: {di.get('hosting_provider', 'Unknown')}\n"
                f"- Flagged Feeds: {', '.join(tf.get('matched_feeds', [])) if tf.get('flagged') else 'None'}\n"
                f"- Lexical Signals: {json.dumps(lf)}"
            )

        grok_reply = _call_grok_llm(
            [{"role": m.role, "content": m.content} for m in chat_req.messages],
            system_context
        )
        if grok_reply:
            return ChatResponse(role="assistant", content=grok_reply)

    # 2. Rule-based Heuristic Engine (Clean, Accurate, Structured Fallback)
    query = last_user_message.lower()

    if diagnosis and any(kw in query for kw in ["why", "flagged", "phishing", "safe", "explain", "reason", "score", "details", "check"]):
        reasons = []
        wi = diagnosis.whois_info or {}
        si = diagnosis.ssl_info or {}
        lf = diagnosis.lexical_features or {}
        tf = diagnosis.threat_feeds or {}
        di = diagnosis.dns_info or {}

        # Domain age
        age = wi.get("domain_age_days", 365)
        if 0 < age < 90:
            reasons.append(
                f"• **Domain Age Vulnerability:** Registered only **{age} days ago** (Registrar: `{wi.get('registrar', 'Unknown')}`). Phishing infrastructure is typically disposable and freshly created."
            )
        elif age >= 365:
            reasons.append(
                f"• **Established Domain History:** Registered for **{age} days** ({round(age/365, 1)} years), demonstrating established domain longevity."
            )

        # SSL status
        if not si.get("valid") or si.get("error"):
            reasons.append(
                "• **Insecure SSL/TLS Connection:** Certificate handshake failed or is untrusted. Credentials transmitted here are vulnerable to interception."
            )
        else:
            reasons.append(
                f"• **Valid SSL Certificate:** Encrypted with valid certificate issued by `{si.get('issuer', 'Standard CA')}`."
            )

        # Keywords in URL
        if lf.get("has_login_keyword"):
            reasons.append(
                "• **Suspicious Authentication Keywords:** URL path contains sensitive keywords (`login`, `verify`, `account`, or `secure`)."
            )

        # External feeds
        if tf.get("flagged"):
            feeds = ", ".join(tf.get("matched_feeds", []))
            reasons.append(f"• **Blacklist Feed Match:** Actively listed on threat intelligence databases: **{feeds}**.")

        # DNS resolution
        if di.get("ips"):
            reasons.append(f"• **Hosting Resolution:** Resolves to `{', '.join(di['ips'][:2])}` hosted on `{di.get('hosting_provider', 'Cloud Infrastructure')}`.")

        factors = "\n".join(reasons)
        verdict_badge = "🚨 CRITICAL THREAT" if diagnosis.prediction == "Phishing" else ("⚠️ SUSPICIOUS" if diagnosis.prediction == "Suspicious" else "✅ VERIFIED SAFE")

        reply = (
            f"### Threat Intelligence Assessment for `{diagnosis.url}`\n\n"
            f"**Verdict:** {verdict_badge} | **Composite Risk Score:** `{diagnosis.risk_score}/100`\n\n"
            f"#### Technical Indicators Identified:\n"
            f"{factors}\n\n"
            f"#### Recommended Defense Action:\n"
            + (
                "1. **Do not input credentials**, passwords, or multi-factor authentication (MFA) codes.\n"
                "2. **Block this domain** on company DNS/firewall gateways.\n"
                "3. Verify the sender's email headers if this URL was received via email or SMS."
                if diagnosis.prediction != "Safe" else
                "1. The domain exhibits normal structural and technical characteristics.\n"
                "2. Ensure standard vigilance before entering sensitive financial information."
            )
        )

    elif any(kw in query for kw in ["typosquat", "similarity", "impersonat", "fake domain", "spoof"]):
        reply = (
            "### Typosquatting & Domain Spoofing Analysis 🛡️\n\n"
            "**Typosquatting** is a social engineering technique where attackers register domains visually similar to reputable brands.\n\n"
            "#### Common Impersonation Patterns:\n"
            "• **Character Substitution (Homoglyphs/Leetspeak):** `paypa1.com`, `g00gle.com`\n"
            "• **Combosquatting & Affixation:** `paypal-security-update.com`, `login-chasebank.net`\n"
            "• **Omission/Addition:** `amzon.com`, `facbook-verify.org`\n\n"
            "#### PhishGuard Detection Strategy:\n"
            "PhishGuard AI combines **Levenshtein distance scoring**, **SLD tokenization**, and **leetspeak normalization tables** to catch impersonation attempts in real-time."
        )

    elif any(kw in query for kw in ["protect", "safe", "tip", "advice", "credential", "mfa", "2fa", "best practice"]):
        reply = (
            "### Enterprise Phishing Defense Protocols 🛡️\n\n"
            "1. **Enforce FIDO2 / WebAuthn Hardware Keys:** Hardware security keys (YubiKey/Passkeys) are cryptographically bound to the authentic domain and cannot be phished by reverse proxies.\n"
            "2. **Verify Second-Level Domains (SLDs):** Check the root domain before entering credentials (e.g. `login.company.com` vs `company.com.attacker.com`).\n"
            "3. **Use Dedicated Password Managers:** Password managers will only auto-fill credentials on exact domain matches.\n"
            "4. **Monitor Critical Domains in Watchlist:** Add your company's core assets to the **PhishGuard Watchlist** to monitor SSL expiration and threat statuses."
        )

    else:
        reply = (
            "### PhishGuard AI Cyber Co-pilot 🛡️\n\n"
            "I can assist you with real-time threat analysis, domain verification, and security mitigation.\n\n"
            "**Key Capabilities:**\n"
            "• **Scan Diagnostics:** Ask *'Why was this domain flagged?'* to get an itemized risk breakdown.\n"
            "• **Typosquatting Checks:** Ask about brand impersonation heuristics.\n"
            "• **Defense Best Practices:** Inquire about credential protection and enterprise domain hygiene."
        )

    return ChatResponse(role="assistant", content=reply)


def _extract_first_json(text: str) -> Optional[dict]:
    """Extracts the first valid JSON object from LLM response."""
    if not text:
        return None
    cleaned = _clean_markdown_response(text)
    # Direct parse attempt
    try:
        res = json.loads(cleaned)
        if isinstance(res, dict):
            return res
    except Exception:
        pass

    # Find first {
    first_idx = cleaned.find('{')
    if first_idx != -1:
        decoder = json.JSONDecoder()
        try:
            obj, _ = decoder.raw_decode(cleaned[first_idx:])
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

        # Try between first { and last }
        last_idx = cleaned.rfind('}')
        if last_idx > first_idx:
            try:
                obj = json.loads(cleaned[first_idx:last_idx + 1])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
    return None


@router.post("/inspect-content", response_model=InspectContentResponse)
def inspect_content(
    payload: InspectContentSchema,
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Analyzes suspicious email text, SMS messages, or HTML script payloads for phishing markers.
    Utilizes xAI Grok / Groq API with structured JSON response parser and heuristic fallback.
    """
    raw_content = payload.content.strip()
    if not raw_content:
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    # 1. Attempt Grok / Groq API Inspection with strictly enforced JSON schema
    if GROK_API_KEY:
        system_prompt = (
            "You are a Principal Cyber Threat Analyst. Inspect the provided content for phishing, credential theft, and social engineering.\n"
            "You MUST respond ONLY with a raw JSON object (no markdown fences, no explanatory pre-text) matching this exact schema:\n"
            "{\n"
            '  "risk_level": "Safe" | "Suspicious" | "Phishing / Malicious",\n'
            '  "analysis": "2-3 sentences explaining the technical threat posture and coercion mechanisms.",\n'
            '  "indicators": ["Indicator 1", "Indicator 2", "Indicator 3"],\n'
            '  "recommendation": "1-2 actionable defense steps for the user or SOC team."\n'
            "}"
        )
        user_msg = f"Analyze the following {payload.content_type} snippet:\n\n{raw_content[:4000]}"
        grok_out = _call_grok_llm([{"role": "user", "content": user_msg}], system_prompt)
        
        if grok_out:
            parsed = _extract_first_json(grok_out)
            if parsed:
                risk_lvl = parsed.get("risk_level", "Suspicious")
                if risk_lvl not in ["Safe", "Suspicious", "Phishing / Malicious"]:
                    risk_lvl = "Phishing / Malicious" if "phish" in str(risk_lvl).lower() or "mal" in str(risk_lvl).lower() else "Suspicious"

                indicators_list = parsed.get("indicators", [])
                if isinstance(indicators_list, str):
                    indicators_list = [indicators_list]

                return InspectContentResponse(
                    risk_level=risk_lvl,
                    analysis=parsed.get("analysis", "AI threat evaluation completed."),
                    indicators=indicators_list if indicators_list else ["Evaluated by AI LLM Engine"],
                    recommendation=parsed.get("recommendation", "Exercise caution when interacting with unverified content.")
                )

    # 2. Heuristic Rule-Based Content Analyzer (Accurate Fallback)
    content_lower = raw_content.lower()
    indicators = []
    
    urgency_keywords = ["urgent", "suspended", "immediately", "verify your account", "unauthorized access", "action required", "within 24 hours", "account locked"]
    cred_keywords = ["password", "ssn", "seed phrase", "credit card", "billing update", "login here", "click link", "confirm identity", "passcode"]
    html_markers = ["<script", "eval(", "unescape(", "document.location", "iframe", "type=\"password\"", "window.location", "atob("]

    for kw in urgency_keywords:
        if kw in content_lower:
            indicators.append(f"Psychological Coercion: '{kw}'")

    for kw in cred_keywords:
        if kw in content_lower:
            indicators.append(f"Sensitive Credential Prompt: '{kw}'")

    for hm in html_markers:
        if hm in content_lower:
            indicators.append(f"Suspicious Web/Script Construct: '{hm}'")

    # Determine risk level
    if len(indicators) >= 3:
        risk_level = "Phishing / Malicious"
    elif len(indicators) >= 1:
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"

    analysis = (
        f"Evaluated {len(raw_content)} characters of {payload.content_type}. "
        f"Identified {len(indicators)} risk marker(s) typical of credential harvesting and social engineering campaigns."
        if indicators else
        f"Analyzed {len(raw_content)} characters of {payload.content_type}. No prominent social engineering or obfuscated script patterns detected."
    )
    
    recommendation = (
        "Do not click embedded links, download attachments, or input credentials. Forward the message to your security operations team."
        if risk_level != "Safe"
        else "No immediate risk indicators found. Maintain standard verification procedures."
    )

    return InspectContentResponse(
        risk_level=risk_level,
        analysis=analysis,
        indicators=indicators if indicators else ["No explicit malicious heuristics triggered"],
        recommendation=recommendation
    )
