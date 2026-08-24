# REST API Specifications: PhishGuard AI

FastAPI endpoints run under `http://localhost:8000`. Swagger specs are available at `/api/docs` and Redoc at `/api/redoc`.

## 1. Authentication Endpoints

### POST `/api/auth/register`
*   **Access**: Public
*   **Body**:
    ```json
    {
      "email": "dev@company.com",
      "password": "strongPassword123"
    }
    ```
*   **Response (201 Created)**:
    ```json
    {
      "message": "Registration successful",
      "email": "dev@company.com"
    }
    ```

### POST `/api/auth/login`
*   **Access**: Public
*   **Body**: Same as registration.
*   **Response (200 OK)**:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
      "token_type": "bearer",
      "email": "dev@company.com"
    }
    ```

### GET `/api/auth/me`
*   **Access**: Authenticated (Bearer Token in headers)
*   **Response (200 OK)**:
    ```json
    {
      "email": "dev@company.com",
      "id": 1,
      "created_at": "2026-06-16T12:00:00"
    }
    ```

---

## 2. Threat Analysis Endpoints

### POST `/api/scan`
*   **Access**: Public / Authenticated (auto-saves history to account if token provided)
*   **Body**:
    ```json
    {
      "url": "https://paypal-security-update.com/login",
      "html_content": null
    }
    ```
*   **Response (200 OK)**:
    ```json
    {
      "scan_id": 1,
      "url": "https://paypal-security-update.com/login",
      "domain": "paypal-security-update.com",
      "risk_score": 98.4,
      "prediction": "Phishing",
      "reasons": [
        "Flagged by threat feeds: PhishTank",
        "Domain is very young (Age: 5 days)",
        "Contains highly suspicious credentials keyword in URL"
      ],
      "xai_explanations": [
        { "factor": "Flagged by threat feeds: PhishTank", "severity": "high" }
      ],
      "whois_info": {
        "domain_age_days": 5,
        "registrar": "NameCheap Inc.",
        "creation_date": "2026-06-11T00:00:00",
        "expiration_date": "2027-06-11T00:00:00",
        "country": "US"
      },
      "ssl_info": {
        "valid": false,
        "issuer": "None",
        "expiration_date": "None",
        "cipher": "None",
        "error": "Insecure Connection"
      },
      "dns_info": {
        "ips": ["182.16.2.8"],
        "mx_servers": [],
        "ns_servers": ["ns1.namecheap.com"],
        "hosting_provider": "Generic Cloud Provider"
      },
      "threat_feeds": {
        "flagged": true,
        "matched_feeds": ["PhishTank"]
      }
    }
    ```

### GET `/api/history`
*   **Access**: Authenticated (Bearer Token in headers)
*   **Response (200 OK)**:
    ```json
    [
      {
        "id": 1,
        "url": "https://paypal-security-update.com/login",
        "risk_score": 98.4,
        "prediction": "Phishing",
        "created_at": "2026-06-16T12:05:00"
      }
    ]
    ```

---

## 3. PDF Report Export

### GET `/api/report/{scan_id}`
*   **Access**: Public / Authenticated
*   **Response**: Binary stream of a standard `.pdf` document containing threat metrics suitable for corporate archiving.

---

## 4. Threat Feeds & AI Assistant

### GET `/api/threats/feed`
*   **Access**: Public
*   **Response**: Real-time list of detected threat domains.

### GET `/api/threats/map`
*   **Access**: Public
*   **Response**: Array of global threat attack coordinates with latitude, longitude, and intensity weight.

### GET `/api/stats`
*   **Access**: Public
*   **Response**: Live platform statistics (total scans, threats detected, accuracy, users).

### POST `/api/ai/chat`
*   **Access**: Public
*   **Body**:
    ```json
    {
      "messages": [
        { "role": "user", "content": "Why is this site flagged?" }
      ],
      "url_context": "https://paypal-security-update.com/login"
    }
    ```
*   **Response**:
    ```json
    {
      "role": "assistant",
      "content": "This site is flagged as PHISHING because it has an age of 5 days, lacks SSL encryption, and has been reported in PhishTank database."
    }
    ```

### POST `/api/ai/inspect-content`
*   **Access**: Public / Authenticated
*   **Body**:
    ```json
    {
      "content": "URGENT: Your account is suspended. Click here to verify password.",
      "content_type": "email_or_text"
    }
    ```
*   **Response**:
    ```json
    {
      "analysis": "Identified multiple social engineering markers.",
      "risk_level": "Phishing / Malicious",
      "indicators": ["Urgency / Coercion Keyword Detected: 'urgent'", "Credential / Sensitive Data Prompt: 'password'"],
      "recommendation": "Do not click embedded links or enter credentials."
    }
    ```

---

## 5. Network & Domain Diagnostics

### GET `/api/whois?domain={domain}`
*   **Access**: Public
*   **Response**: WHOIS registrar, creation date, expiration date, and domain age in days.

### GET `/api/ssl?domain={domain}`
*   **Access**: Public
*   **Response**: SSL certificate validity status, issuer, expiration, and cipher suite.

### GET `/api/dns?domain={domain}`
*   **Access**: Public
*   **Response**: Resolved A records (IPs), MX mail servers, and NS nameservers.

---

## 6. User Security Hub

### GET `/api/user/stats`
*   **Access**: Authenticated (Bearer Token in headers)
*   **Response**: Aggregated user security score card (total scans, breakdown, threat rate, security grade A+ to F).

### GET `/api/user/watchlist`
*   **Access**: Authenticated
*   **Response**: Array of monitored domain assets with SSL validity, days until expiration, and risk score.

### POST `/api/user/watchlist`
*   **Access**: Authenticated
*   **Body**:
    ```json
    {
      "domain": "company-portal.com",
      "label": "Corporate Portal"
    }
    ```

### DELETE `/api/user/watchlist/{id}`
*   **Access**: Authenticated
*   **Response**: Removes the specified domain from monitoring.

### DELETE `/api/user/history/{scan_id}`
*   **Access**: Authenticated
*   **Response**: Deletes personal scan record from user's history.
