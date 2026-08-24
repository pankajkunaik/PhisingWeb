import socket
import ssl
import datetime
import whois
import dns.resolver
from difflib import SequenceMatcher
from urllib.parse import urlparse
import json
import os
import pickle
import numpy as np

import sys

# Ensure the root workspace directory is in python path to resolve ml features absolutely
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Add app dir for local imports
_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from ml.features import extract_all_features, FEATURE_KEYS
from core.config import ML_MODEL_JSON, ML_MODEL_PKL, GOOGLE_SAFE_BROWSING_API_KEY
import requests

# Top popular brand domains for typosquatting detection
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "twitter.com", "linkedin.com", "netflix.com", 
    "amazon.com", "microsoft.com", "apple.com", "github.com", "paypal.com", 
    "ebay.com", "yahoo.com", "instagram.com", "zoom.us", "salesforce.com", 
    "dropbox.com", "adobe.com", "chase.com", "wellsfargo.com", "bankofamerica.com"
]

def check_typosquatting(domain: str) -> dict:
    """Checks if a domain is typosquatted against top brand domains using SLD tokenization and leetspeak analysis."""
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
        
    if not domain:
        return {"is_typosquat": False, "matched_brand": None, "similarity": 0.0}

    # Extract Second-Level Domain (SLD) if possible (e.g. login.paypal.com -> paypal.com)
    parts = domain.split(".")
    sld = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    sld_name = parts[-2] if len(parts) >= 2 else domain.split(".")[0]

    # Leetspeak translation table
    leetspeak_trans = str.maketrans({
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b', '@': 'a', '$': 's'
    })
    normalized_sld_name = sld_name.translate(leetspeak_trans)

    for brand in POPULAR_DOMAINS:
        brand_name = brand.split(".")[0]
        
        # Exact match or legitimate subdomains (e.g. login.paypal.com or paypal.com)
        if domain == brand or domain.endswith("." + brand) or sld == brand:
            return {"is_typosquat": False, "matched_brand": None, "similarity": 1.0}
            
        # 1. Normalized leetspeak match (e.g., paypa1 -> paypal, g00gle -> google)
        if normalized_sld_name == brand_name or normalized_sld_name.startswith(brand_name + "-") or normalized_sld_name.endswith("-" + brand_name):
            return {
                "is_typosquat": True,
                "matched_brand": brand,
                "similarity": 0.95
            }

        # 2. Tokenized hyphen/sub-word similarity check (e.g. paypa1-security)
        tokens = sld_name.split("-")
        for token in tokens:
            token_norm = token.translate(leetspeak_trans)
            if token_norm == brand_name and sld != brand:
                return {
                    "is_typosquat": True,
                    "matched_brand": brand,
                    "similarity": 0.92
                }
            
            token_sim = SequenceMatcher(None, token_norm, brand_name).ratio()
            if 0.78 <= token_sim < 1.0:
                return {
                    "is_typosquat": True,
                    "matched_brand": brand,
                    "similarity": round(token_sim, 3)
                }

        # 3. Overall SLD name similarity
        similarity = SequenceMatcher(None, normalized_sld_name, brand_name).ratio()
        if 0.75 <= similarity < 1.0:
            return {
                "is_typosquat": True,
                "matched_brand": brand,
                "similarity": round(similarity, 3)
            }
            
    return {"is_typosquat": False, "matched_brand": None, "similarity": 0.0}

def get_dns_info(domain: str) -> dict:
    """Performs DNS queries to resolve A, MX, and NS records."""
    info = {"ips": [], "mx_servers": [], "ns_servers": [], "hosting_provider": "Unknown"}
    
    # Clean domain
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
        
    if not domain:
        return info
        
    # A records (IPs)
    try:
        answers = dns.resolver.resolve(domain, 'A')
        info["ips"] = [str(rdata) for rdata in answers]
    except Exception:
        pass
        
    # MX records (Mail servers)
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        info["mx_servers"] = [str(rdata.exchange) for rdata in answers]
    except Exception:
        pass
        
    # NS records (Nameservers)
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        info["ns_servers"] = [str(rdata) for rdata in answers]
    except Exception:
        pass
        
    # Try to guess hosting from IPs
    if info["ips"]:
        # Mock lookup for popular IPs to keep it responsive, or standard check
        first_ip = info["ips"][0]
        if first_ip.startswith(("34.", "35.", "104.", "172.")):
            info["hosting_provider"] = "Google Cloud / Cloudflare"
        elif first_ip.startswith(("52.", "54.", "3.")):
            info["hosting_provider"] = "Amazon Web Services"
        elif first_ip.startswith("185."):
            info["hosting_provider"] = "DigitalOcean / Linode"
        else:
            info["hosting_provider"] = "Generic Cloud Provider"
            
    return info

def get_ssl_info(domain: str) -> dict:
    """Retrieves SSL Certificate details by connecting to port 443."""
    info = {
        "valid": False,
        "issuer": "None",
        "expiration_date": "None",
        "cipher": "None",
        "error": "Not Secure / No Certificate"
    }
    
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
        
    if not domain:
        return info

    def parse_cert(cert, cipher):
        exp_date_str = cert.get('notAfter')
        if exp_date_str:
            try:
                exp_date = datetime.datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                info["expiration_date"] = exp_date.isoformat()
                info["valid"] = exp_date > datetime.datetime.utcnow()
            except Exception:
                info["expiration_date"] = str(exp_date_str)
                info["valid"] = True

        issuer_tuple = cert.get('issuer', ())
        issuer_name = "Unknown Issuer"
        for rdns in issuer_tuple:
            for attr, value in rdns:
                if attr == 'organizationName':
                    issuer_name = value
                    break
        info["issuer"] = issuer_name
        if cipher:
            info["cipher"] = f"{cipher[0]} ({cipher[1]})"

    # Attempt 1: Standard Verified SSL Check
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                parse_cert(cert, cipher)
                info["error"] = None
                return info
    except Exception as err_verified:
        info["error"] = str(err_verified)

    # Attempt 2: Unverified SSL Check to extract certificate metadata even if untrusted/expired
    try:
        unverified_ctx = ssl._create_unverified_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with unverified_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                if cert:
                    parse_cert(cert, cipher)
                info["valid"] = False  # Mark as invalid because verification failed in attempt 1
    except Exception:
        pass
        
    return info

def get_whois_info(domain: str) -> dict:
    """Queries WHOIS records for domain age, registrar, and country."""
    info = {
        "domain_age_days": 0,
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "country": "Unknown",
        "is_whois_verified": False
    }
    
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
        
    if not domain:
        return info
        
    try:
        w = whois.whois(domain)
        
        # Parse creation date
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
            
        if isinstance(created, datetime.datetime):
            info["creation_date"] = created.isoformat()
            age_delta = datetime.datetime.now() - created
            info["domain_age_days"] = max(0, age_delta.days)
            info["is_whois_verified"] = True
        elif created:
            info["creation_date"] = str(created)
            info["is_whois_verified"] = True
            
        # Parse expiration date
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if isinstance(expires, datetime.datetime):
            info["expiration_date"] = expires.isoformat()
        elif expires:
            info["expiration_date"] = str(expires)
            
        # Parse registrar
        info["registrar"] = str(w.registrar) if w.registrar else "Unknown"
        # Parse country
        info["country"] = str(w.country) if w.country else "Unknown"
        
    except Exception:
        info["is_whois_verified"] = False
        
    return info

def run_ml_prediction(features_dict: dict) -> tuple:
    """Runs prediction using saved XGBoost / Pickle model. Returns (pred_label, probability)."""
    # Use absolute paths from config — works regardless of working directory
    model_paths = [
        (ML_MODEL_JSON, "json"),
        (ML_MODEL_PKL, "pkl"),
    ]

    model = None
    model_type = None

    for path, ftype in model_paths:
        if os.path.exists(path):
            if ftype == "json":
                try:
                    import xgboost as xgb
                    model = xgb.XGBClassifier()
                    model.load_model(path)
                    model_type = "xgboost"
                    break
                except ImportError:
                    pass
            elif ftype == "pkl":
                try:
                    with open(path, "rb") as f:
                        model = pickle.load(f)
                    model_type = "random_forest"
                    break
                except Exception:
                    pass
                    
    # If no model found, return a default heuristic prediction
    if model is None:
        # Mock prediction based on features
        score = 0
        if features_dict.get("qty_dots", 0) > 3: score += 20
        if features_dict.get("qty_hyphens", 0) > 2: score += 15
        if features_dict.get("has_login_keyword", 0) == 1: score += 35
        if features_dict.get("is_https", 0) == 0: score += 20
        if features_dict.get("external_links_ratio", 0.0) > 0.5: score += 30
        if features_dict.get("has_unsafe_form", 0) == 1: score += 25
        
        prob = min(1.0, score / 100.0)
        label = 1 if prob >= 0.5 else 0
        return label, prob
        
    # Prepare vector
    vector = [features_dict.get(k, 0) for k in FEATURE_KEYS]
    x_input = np.array([vector])
    
    try:
        prob = float(model.predict_proba(x_input)[0, 1])
        label = int(model.predict(x_input)[0])
        return label, prob
    except Exception:
        # Fallback in case of shape mismatch
        return 0, 0.05

def query_google_safe_browsing(target_url: str, domain: str = None) -> list:
    """Queries Google Safe Browsing API v4 with the configured API key."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return []
    
    entries = [{"url": target_url}]
    if domain and domain not in target_url:
        entries.append({"url": f"http://{domain}/"})

    payload = {
        "client": {
            "clientId": "phishguard-ai",
            "clientVersion": "2.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE", 
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": entries
        }
    }
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    try:
        response = requests.post(endpoint, json=payload, timeout=3.0)
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            threat_labels = []
            for m in matches:
                tt = m.get("threatType", "MALICIOUS")
                threat_labels.append(f"Google Safe Browsing ({tt})")
            return threat_labels
    except Exception:
        pass
    return []

def check_threat_feeds(domain: str, url: str = None) -> dict:
    """Checks live Google Safe Browsing API and threat intelligence databases."""
    domain_clean = domain.lower().strip()
    if domain_clean.startswith("www."):
        domain_clean = domain_clean[4:]
        
    feeds_matched = []

    # 1. Live Google Safe Browsing API check
    if url or domain_clean:
        target = url or f"http://{domain_clean}/"
        gsb_matches = query_google_safe_browsing(target, domain_clean)
        if gsb_matches:
            feeds_matched.extend(gsb_matches)
        
    return {
        "flagged": len(feeds_matched) > 0,
        "matched_feeds": list(dict.fromkeys(feeds_matched))
    }

def analyze_url(url: str, html_content: str = None) -> dict:
    """Executes the full composite phishing scan on a URL."""
    # 1. Parsing and Lexical Extraction
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # default to secure check
        
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
    except Exception:
        domain = ""

    # If html_content is not provided, attempt a live HTTP GET fetch to analyze real page DOM
    if not html_content and url.startswith(("http://", "https://")):
        try:
            resp = requests.get(
                url, 
                timeout=2.5, 
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuardAI/2.0"}
            )
            if resp.status_code == 200:
                html_content = resp.text
        except Exception:
            pass
        
    features = extract_all_features(url, html_content)
    
    # 2. Advanced Diagnostic Steps (typosquatting, threat feeds, DNS, WHOIS, SSL)
    typosquat = check_typosquatting(domain)
    threat_feed = check_threat_feeds(domain, url)
    dns_info = get_dns_info(domain)
    ssl_info = get_ssl_info(domain)
    whois_info = get_whois_info(domain)
    
    # 3. Model Prediction
    ml_label, ml_prob = run_ml_prediction(features)
    
    # 4. Composite Risk Score Calculation (0 - 100)
    risk_score = float(ml_prob * 70.0)  # Base ML score contributes up to 70 points
    
    # Add adjustments based on heuristics and secondary checks
    reasons = []
    
    if typosquat["is_typosquat"]:
        risk_score += 25.0
        reasons.append(f"Typosquatting detected: resembles {typosquat['matched_brand']} (similarity: {int(typosquat['similarity'] * 100)}%)")
        
    if threat_feed["flagged"]:
        risk_score = 100.0  # Force maximum threat if present in known threat feeds
        reasons.append(f"Flagged by threat feeds: {', '.join(threat_feed['matched_feeds'])}")
        
    if not ssl_info["valid"] or ssl_info["error"]:
        risk_score += 15.0
        reasons.append("Missing or invalid SSL/TLS Certificate (Insecure connection)")
        
    if whois_info.get("is_whois_verified") and 0 < whois_info["domain_age_days"] < 90:
        risk_score += 15.0
        reasons.append(f"Domain is very young (Age: {whois_info['domain_age_days']} days), common for phishing campaigns")
        
    if features.get("has_login_keyword") == 1:
        risk_score += 10.0
        reasons.append("Contains highly suspicious credentials keyword in URL")
        
    if features.get("qty_subdomains", 0) >= 3:
        risk_score += 10.0
        reasons.append(f"Excessive number of subdomains ({features['qty_subdomains']})")
        
    if features.get("external_links_ratio", 0.0) > 0.6:
        risk_score += 10.0
        reasons.append(f"High percentage of external assets/links ({int(features['external_links_ratio'] * 100)}%)")
        
    # Cap score between 0 and 100
    risk_score = max(0.0, min(100.0, risk_score))
    
    # Classify rating
    if risk_score < 30.0:
        prediction = "Safe"
    elif risk_score < 70.0:
        prediction = "Suspicious"
    else:
        prediction = "Phishing"
        
    # Default message if no reasons triggered but score is high
    if not reasons and risk_score >= 30.0:
        reasons.append("URL structural properties match signatures of known phishing heuristics")
        
    # Structure explainable XAI payload
    xai_explanations = []
    for reason in reasons:
        xai_explanations.append({
            "factor": reason,
            "severity": "high" if "threat" in reason.lower() or "typosquat" in reason.lower() or risk_score >= 70.0 else "medium"
        })
        
    # Convert numpy types to native Python types for clean JSON serialization
    lexical_clean = {}
    for k in FEATURE_KEYS:
        if k in features and k not in ["external_links_ratio", "iframe_present", "disables_right_click", "has_unsafe_form", "favicon_external"]:
            lexical_clean[k] = int(features[k])

    # Final response dictionary
    return {
        "url": url,
        "domain": domain,
        "risk_score": round(float(risk_score), 1),
        "prediction": prediction,
        "reasons": reasons,
        "xai_explanations": xai_explanations,
        "lexical_features": lexical_clean,
        "html_features": {
            "external_links_ratio": round(float(features.get("external_links_ratio", 0.0)), 3),
            "iframe_present": int(features.get("iframe_present", 0)),
            "disables_right_click": int(features.get("disables_right_click", 0)),
            "has_unsafe_form": int(features.get("has_unsafe_form", 0)),
            "favicon_external": int(features.get("favicon_external", 0))
        },
        "whois_info": whois_info,
        "ssl_info": ssl_info,
        "dns_info": dns_info,
        "threat_feeds": threat_feed
    }
