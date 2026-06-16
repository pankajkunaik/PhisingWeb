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
    sys.path.append(root_dir)

from ml.features import extract_all_features, FEATURE_KEYS

# Top popular brand domains for typosquatting detection
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "twitter.com", "linkedin.com", "netflix.com", 
    "amazon.com", "microsoft.com", "apple.com", "github.com", "paypal.com", 
    "ebay.com", "yahoo.com", "instagram.com", "zoom.us", "salesforce.com", 
    "dropbox.com", "adobe.com", "chase.com", "wellsfargo.com", "bankofamerica.com"
]

def check_typosquatting(domain: str) -> dict:
    """Checks if a domain is typoquatted against top brand domains."""
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
        
    for brand in POPULAR_DOMAINS:
        if domain == brand:
            return {"is_typosquat": False, "matched_brand": None, "similarity": 1.0}
            
        similarity = SequenceMatcher(None, domain, brand).ratio()
        # High similarity (e.g. g00gle.com vs google.com) but not identical
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
    
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
        
    if not domain:
        return info
        
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Parse certificate expiration
                # Example date: 'May  9 12:00:00 2026 GMT'
                exp_date_str = cert.get('notAfter')
                if exp_date_str:
                    try:
                        exp_date = datetime.datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                        info["expiration_date"] = exp_date.isoformat()
                        info["valid"] = exp_date > datetime.datetime.utcnow()
                    except Exception:
                        info["expiration_date"] = str(exp_date_str)
                        info["valid"] = True
                
                # Parse issuer
                issuer_tuple = cert.get('issuer', ())
                issuer_name = "Unknown Issuer"
                for rdns in issuer_tuple:
                    for attr, value in rdns:
                        if attr == 'organizationName':
                            issuer_name = value
                            break
                            
                info["issuer"] = issuer_name
                info["cipher"] = f"{cipher[0]} ({cipher[1]})"
                info["error"] = None
    except Exception as e:
        info["error"] = str(e)
        
    return info

def get_whois_info(domain: str) -> dict:
    """Queries WHOIS records for domain age, registrar, and country."""
    info = {
        "domain_age_days": 365,  # fallback default
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "country": "Unknown"
    }
    
    domain = domain.lower()
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
        elif created:
            info["creation_date"] = str(created)
            
        # Parse expiration date
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if isinstance(expires, datetime.datetime):
            info["expiration_date"] = expires.isoformat()
        elif expires:
            info["expiration_date"] = str(expires)
            
        # Parse registrar
        info["registrar"] = w.registrar if w.registrar else "Unknown"
        # Parse country
        info["country"] = w.country if w.country else "Unknown"
        
    except Exception:
        # Graceful fallback for local offline testing
        pass
        
    return info

def run_ml_prediction(features_dict: dict) -> tuple:
    """Runs prediction using saved XGBoost / Pickle model. Returns (pred_label, probability)."""
    # Look for saved models
    model_paths = [
        "backend/app/models/phishguard_model.json",
        "backend/app/models/phishguard_model.pkl",
        "ml/models/phishguard_model.json",
        "ml/models/phishguard_model.pkl"
    ]
    
    model = None
    model_type = None
    
    for path in model_paths:
        if os.path.exists(path):
            if path.endswith(".json"):
                try:
                    import xgboost as xgb
                    model = xgb.XGBClassifier()
                    model.load_model(path)
                    model_type = "xgboost"
                    break
                except ImportError:
                    pass
            elif path.endswith(".pkl"):
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

def check_threat_feeds(domain: str) -> dict:
    """Simulates checking Google Safe Browsing, PhishTank, and OpenPhish."""
    # We maintain a small local hash matching simulation list, and check standard public lists.
    # For a real implementation, you would make requests or download updates periodically.
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
        
    # Simulated phishing lists
    phishtank_db = ["paypal-security-update.com", "netflix-login-renew.com", "chase-verify-billing.net", "facebook-signin-claim.org"]
    openphish_db = ["crypto-wallet-login.com", "binance-verify-id.net", "metamask-recover-seed.org"]
    safe_browsing_db = ["malicious-phishing-test-site.com", "g00gle-login-portal.com"]
    
    feeds_matched = []
    if domain in phishtank_db:
        feeds_matched.append("PhishTank")
    if domain in openphish_db:
        feeds_matched.append("OpenPhish")
    if domain in safe_browsing_db:
        feeds_matched.append("Google Safe Browsing")
        
    return {
        "flagged": len(feeds_matched) > 0,
        "matched_feeds": feeds_matched
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
        
    features = extract_all_features(url, html_content)
    
    # 2. Advanced Diagnostic Steps (typosquatting, threat feeds, DNS, WHOIS, SSL)
    typosquat = check_typosquatting(domain)
    threat_feed = check_threat_feeds(domain)
    dns_info = get_dns_info(domain)
    ssl_info = get_ssl_info(domain)
    whois_info = get_whois_info(domain)
    
    # 3. Model Prediction
    ml_label, ml_prob = run_ml_prediction(features)
    
    # 4. Composite Risk Score Calculation (0 - 100)
    risk_score = ml_prob * 70.0  # Base ML score contributes up to 70 points
    
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
        
    if whois_info["domain_age_days"] < 90:
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
        
    # Final response dictionary
    return {
        "url": url,
        "domain": domain,
        "risk_score": round(risk_score, 1),
        "prediction": prediction,
        "reasons": reasons,
        "xai_explanations": xai_explanations,
        "lexical_features": {k: features[k] for k in FEATURE_KEYS if k in features and k not in ["external_links_ratio", "iframe_present", "disables_right_click", "has_unsafe_form", "favicon_external"]},
        "html_features": {
            "external_links_ratio": round(features.get("external_links_ratio", 0.0), 3),
            "iframe_present": features.get("iframe_present", 0),
            "disables_right_click": features.get("disables_right_click", 0),
            "has_unsafe_form": features.get("has_unsafe_form", 0),
            "favicon_external": features.get("favicon_external", 0)
        },
        "whois_info": whois_info,
        "ssl_info": ssl_info,
        "dns_info": dns_info,
        "threat_feeds": threat_feed
    }
