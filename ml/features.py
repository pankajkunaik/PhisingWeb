import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# List of common URL shorteners
SHORTENERS = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl.com",
    "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu",
    "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm",
    "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com",
    "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "lnkd.in",
    "db.tt", "qr.ae", "adf.ly", "goo.gl", "bitly.com", "cur.lv", "tiny.cc", "ow.ly",
    "ity.im", "q.gs", "is.gd", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp", "buzurl.com",
    "cutt.us", "u.bb", "yourls.org", "x.co", "prettylinkpro.com", "scrnch.me", "filoops.info",
    "vzturl.com", "qr.net", "1url.com", "tweez.me", "v.gd", "tr.im", "link.zip.net"
}

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "bank", "secure", "account", "verify", "webscr", "ebayisapi",
    "update", "confirm", "wallet", "paypal", "credential", "password", "support",
    "validation", "service", "billing", "recovery", "security", "free", "gift"
]

def check_ip_in_domain(domain: str) -> int:
    """Returns 1 if the domain is an IP address (IPv4 or IPv6), else 0."""
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
    if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
        return 1
    return 0

def extract_lexical_features(url: str) -> dict:
    """Extracts lexical features from a URL string."""
    features = {}
    
    # Ensure scheme is present for parsing
    original_url = url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
    except Exception:
        domain = ""
        path = ""
        
    # Standard lexical checks
    features["url_length"] = len(original_url)
    features["domain_length"] = len(domain)
    features["qty_dots"] = original_url.count(".")
    features["qty_hyphens"] = original_url.count("-")
    features["qty_underline"] = original_url.count("_")
    features["qty_slash"] = original_url.count("/")
    features["qty_question"] = original_url.count("?")
    features["qty_equal"] = original_url.count("=")
    features["qty_at"] = original_url.count("@")
    features["qty_and"] = original_url.count("&")
    features["qty_exclamation"] = original_url.count("!")
    features["qty_tilde"] = original_url.count("~")
    features["qty_comma"] = original_url.count(",")
    features["qty_plus"] = original_url.count("+")
    features["qty_asterisk"] = original_url.count("*")
    features["qty_hashtag"] = original_url.count("#")
    features["qty_dollar"] = original_url.count("$")
    features["qty_percent"] = original_url.count("%")
    
    # Subdomain count
    subdomains = domain.split(".")
    # Remove 'www' from list if present
    if "www" in subdomains:
        subdomains.remove("www")
    # Subdomains quantity is the length of split list minus 1 (for TLD) minus 1 (for main domain), min 0
    features["qty_subdomains"] = max(0, len(subdomains) - 2) if len(subdomains) > 0 else 0
    
    # Advanced lexical checks
    features["has_ip"] = check_ip_in_domain(domain)
    features["is_shortened"] = 1 if domain in SHORTENERS or any(sh in domain for sh in ["bit.ly", "tinyurl.com"]) else 0
    
    # Keyword analysis
    url_lower = original_url.lower()
    features["has_login_keyword"] = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0
    
    # Security of protocol
    features["is_https"] = 1 if url.startswith("https://") else 0
    
    return features

def extract_html_features(html_content: str, domain: str) -> dict:
    """Extracts features from HTML content of a page."""
    features = {
        "external_links_ratio": 0.0,
        "iframe_present": 0,
        "disables_right_click": 0,
        "has_unsafe_form": 0,
        "favicon_external": 0
    }
    
    if not html_content:
        return features
        
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        # 1. External links ratio
        links = soup.find_all("a", href=True)
        total_links = len(links)
        external_links = 0
        
        for link in links:
            href = link["href"].strip()
            if href.startswith(("http://", "https://")):
                parsed_href = urlparse(href)
                href_domain = parsed_href.netloc.lower()
                if href_domain and domain not in href_domain:
                    external_links += 1
            elif href.startswith("//"):
                href_domain = href.split("/")[2].split("?")[0]
                if domain not in href_domain:
                    external_links += 1
                    
        features["external_links_ratio"] = external_links / total_links if total_links > 0 else 0.0
        
        # 2. Iframe presence (sometimes used to embed malicious input forms)
        iframes = soup.find_all("iframe")
        features["iframe_present"] = 1 if len(iframes) > 0 else 0
        
        # 3. Disables right click (using inline script or listeners)
        scripts = soup.find_all("script")
        script_text = "".join([s.string for s in scripts if s.string])
        if "event.button==2" in script_text or "preventDefault()" in script_text and "contextmenu" in script_text:
            features["disables_right_click"] = 1
            
        # 4. Form checks (form action is empty, about:blank, or external)
        forms = soup.find_all("form", action=True)
        for form in forms:
            action = form["action"].strip()
            if action == "" or action.lower() == "about:blank":
                features["has_unsafe_form"] = 1
            elif action.startswith(("http://", "https://")):
                parsed_action = urlparse(action)
                action_domain = parsed_action.netloc.lower()
                if action_domain and domain not in action_domain:
                    features["has_unsafe_form"] = 1
                    
        # 5. Favicon check
        links_fav = soup.find_all("link", rel=lambda x: x and 'icon' in x.lower(), href=True)
        for fav in links_fav:
            href = fav["href"].strip()
            if href.startswith(("http://", "https://")):
                parsed_fav = urlparse(href)
                fav_domain = parsed_fav.netloc.lower()
                if fav_domain and domain not in fav_domain:
                    features["favicon_external"] = 1
                    
    except Exception:
        pass
        
    return features

def extract_all_features(url: str, html_content: str = None) -> dict:
    """Combines lexical and HTML features into a single feature dictionary."""
    features = extract_lexical_features(url)
    
    # Parse domain for HTML check
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        domain = urlparse(url).netloc.lower()
    except Exception:
        domain = ""
        
    html_features = extract_html_features(html_content, domain)
    features.update(html_features)
    
    return features

# List of final feature keys in the exact order required by the ML model
FEATURE_KEYS = [
    "url_length", "domain_length", "qty_dots", "qty_hyphens", "qty_underline",
    "qty_slash", "qty_question", "qty_equal", "qty_at", "qty_and", "qty_exclamation",
    "qty_tilde", "qty_comma", "qty_plus", "qty_asterisk", "qty_hashtag", "qty_dollar",
    "qty_percent", "qty_subdomains", "has_ip", "is_shortened", "has_login_keyword",
    "is_https", "external_links_ratio", "iframe_present", "disables_right_click",
    "has_unsafe_form", "favicon_external"
]

def features_to_vector(features_dict: dict) -> list:
    """Converts a features dictionary to a flat numerical list matching FEATURE_KEYS."""
    return [features_dict.get(k, 0) for k in FEATURE_KEYS]
