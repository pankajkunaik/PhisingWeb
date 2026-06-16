# Architecture Design: PhishGuard AI Platform

PhishGuard AI is a multi-tier website threat detection system combining lexical feature classifiers, network diagnostics (SSL/WHOIS/DNS), known threat feed lists, and typosquatting detection algorithms.

## 1. System Dataflow Diagram
The request analysis cycle operates in a modular pipeline:

```
[User Input URL] 
       │
       ▼
 1. Standardize URL Protocol (HTTP/HTTPS conversion)
       │
       ├───────────────────────────────┐
       ▼                               ▼
 2. Lexical Parsing              3. Brand Typosquatting Checker
 (Features: dots, length, etc.)   (Fuzzy comparison vs Top 50 brands)
       │                               │
       ├───────────────────────────────┤
       ▼                               ▼
 4. Passive Network Resolvers    5. External Threat Feeds
 (WHOIS, DNS records, SSL cert)   (Google Safe Browsing, PhishTank)
       │                               │
       └───────────────┬───────────────┘
                       ▼
             6. ML Ingestion Vector
               (XGBoost Model)
                       │
                       ▼
            7. Scoring Engine (0-100)
                       │
                       ▼
      8. Explainable AI Insights (XAI)
```

---

## 2. Directory Architecture

```
PhishGuard AI/
├── backend/
│   ├── app/
│   │   ├── models/            # Saved XGBoost / RandomForest models
│   │   ├── services/
│   │   │   ├── auth.py        # Hashing and JWT tokens
│   │   │   ├── scanner.py     # Main scanning logic (WHOIS/SSL/DNS)
│   │   │   └── reporter.py    # FPDF2 report compilation
│   │   └── main.py            # FastAPI entrypoint routers & rate limiting
│   └── requirements.txt       # Backend dependencies
│
├── frontend/
│   └── src/
│       └── app/
│           ├── dashboard/     # Interactive Gauge, diagnostics, chat co-pilot
│           ├── globals.css    # Glassmorphic themes & custom scanner keys
│           ├── layout.tsx     # Typography and page templates
│           └── page.tsx       # Landing page, live threat feed, hero scanner
│
├── ml/
│   ├── models/                # Trained artifacts
│   ├── features.py            # Feature extractor
│   └── train.py               # XGBoost synthetic generator and pipeline
│
└── extension/                 # Manifest V3 browser extension
    ├── manifest.json
    ├── popup.html
    ├── popup.css
    ├── popup.js
    └── background.js
```

---

## 3. Composite Risk Scoring Algorithm

The final threat assessment rating (0 to 100) is aggregated using weighting factors:
*   **Base ML Classifier (70%)**: Features compiled in `ml/features.py` are run through the model, yielding a base probability.
*   **Threat Intelligence Overwrite (100%)**: If the domain matches a blacklisted record, the score is forced to 100.
*   **Typosquatting Flag (+25 pts)**: Triggered if domain similarity matches a global target (e.g. `g00gle.com`).
*   **SSL Expiration/Invalidity Check (+15 pts)**: Triggered if socket handshake fails on port 443.
*   **WHOIS Domain Age (+15 pts)**: Triggered if domain registration is under 90 days.
*   **Lexical Key Triggers (+10 pts)**: Triggered if URL path contains keywords like `login`, `verify`, or `billing`.

## 4. Database Schema
*   **Users Table**: Primary key `id`, indexable unique `email`, `password_hash`, status, and registration date.
*   **Scan Records Table**: Primary key `id`, ForeignKey linking `user_id` (supporting anonymous scans as null), `url`, float `risk_score`, text `prediction`, and json serialized columns for `lexical_features`, `html_features`, `whois_info`, `ssl_info`, `dns_info`, and `threat_feeds`.
