# AuthPulse

**Authorization Testing Framework for Bug Bounty Hunting**

AuthPulse automates broken access control testing — OWASP's #1 vulnerability category. It authenticates as two user roles, replays every endpoint with modified auth contexts, and reports where a low-privilege user can access high-privilege data or functionality.

You do the manual validation and write the report. AuthPulse does the boring part.

---

## Installation

```bash
git clone https://github.com/your-org/authpulse
cd authpulse
pip install -e .
```

**Requirements:** Python 3.11+

---

## Quick Start

### 1. Configure

Copy and edit `config.yaml`:

```yaml
target:
  base_url: "https://api.target.com"
  verify_ssl: true

auth:
  method: "bearer_jwt"
  login_endpoint: "/api/auth/login"
  login_method: "POST"
  login_body_template:
    email: "{email}"
    password: "{password}"
  token_location: "response_body"
  token_field: "access_token"
  token_header: "Authorization"
  token_prefix: "Bearer "

users:
  low_priv:
    email: "user@target.com"
    password: "UserPassword123"
    label: "Regular User"
  high_priv:
    email: "admin@target.com"
    password: "AdminPassword123"
    label: "Administrator"
```

### 2. Prepare endpoint list

Use `endpoints/example.json` or export from Burp Suite / ParamSpider:

```json
{
  "endpoints": [
    {"url": "/api/v1/users/{id}", "method": "GET"},
    {"url": "/api/v1/admin/settings", "method": "GET"}
  ]
}
```

Or plain text (`endpoints.txt`):
```
GET /api/v1/users
GET /api/v1/users/123
PUT /api/v1/users/123
GET /api/v1/admin/settings
```

### 3. Run

```bash
# Full scan
authpulse scan --config config.yaml --endpoints endpoints/example.json

# Single endpoint
authpulse scan --config config.yaml --endpoint "/api/v1/users/45" --method GET

# Quick mode (auth tests only, no IDOR/param cycling)
authpulse scan --config config.yaml --endpoints endpoints.json --quick

# Custom output directory
authpulse scan --config config.yaml --endpoints endpoints.json --output ./results

# IDOR tests only
authpulse idor --config config.yaml --endpoints endpoints.json

# Analyse a JWT token
authpulse jwt --config config.yaml --token "eyJhbGciOi..."

# Validate config
authpulse validate-config --config config.yaml
```

---

## What It Tests

### Authentication Tests
| Test | What it detects |
|------|----------------|
| No token | Auth bypass — endpoint accessible without credentials |
| Low-priv on high-priv endpoint | Vertical privilege escalation |
| Malformed token | Token validation missing |
| Expired JWT (alg:none) | Expiry check missing |
| JWT alg:none | Algorithm confusion — unsigned token accepted |

### IDOR Tests
| Test | What it detects |
|------|----------------|
| Sequential ID cycling (1–20) | IDOR — low-priv accessing other users' resources |
| Edge cases (0, -1, MAX_INT) | Boundary condition IDORs |
| UUID variants | UUID-based IDOR |
| Known usernames (admin, root) | Username enumeration + IDOR |

### JWT Manipulation
| Test | What it detects |
|------|----------------|
| Role claim → "admin" (alg:none) | Unsigned role escalation |
| Multiple role values | Role claim not server-validated |

### Parameter Injection
| Test | What it detects |
|------|----------------|
| `?admin=true`, `?role=admin` | Admin param bypass |
| `?debug=true`, `?verbose=1` | Debug mode information disclosure |
| `?include=all`, `?expand=all` | Hidden field exposure |
| `?fields=password,ssn` | Sensitive field enumeration |
| Body: `{"role": "admin"}` | Mass assignment vulnerability |

---

## Demo: OWASP Juice Shop

Juice Shop is a free intentionally-vulnerable app — perfect for safe testing.

```bash
# Start Juice Shop (Docker required)
docker run --rm -p 3000:3000 bkimminich/juice-shop

# Register a regular user at http://localhost:3000

# Run AuthPulse against it
authpulse scan \
  --config demo-juice-shop.yaml \
  --endpoints endpoints/juice-shop-endpoints.json \
  --verbose
```

Expected findings on Juice Shop:
- IDOR on `/rest/basket/{id}` — users can access each other's baskets
- Auth bypass or privilege escalation on `/rest/admin/*` endpoints
- Potential information disclosure on `/api/Users`

---

## Output

### Terminal (real-time)

```
  AuthPulse — Authorization Testing Framework
  Target: https://api.target.com

  ✅ Administrator (admin@target.com)
  ✅ Regular User (user@target.com)

  BASELINE  Administrator: 89 / 89 endpoints accessible
  BASELINE  Regular User:  42 / 89 endpoints accessible

  Scan Starting  89 endpoints × ~12 tests each
  ────────────────────────────────────────────────────────────

🔴 [CRITICAL] GET /api/v1/admin/settings
     No authentication required — returns full admin config
     Confidence: HIGH

🟠 [HIGH] GET /api/v1/users/45
     IDOR: 47/20 IDs accessible. Response includes PII fields: email, phone, last_4_ssn
     Confidence: HIGH
```

### JSON Report (`authpulse-output/authpulse_YYYYMMDD_HHMMSS.json`)

```json
{
  "scan_info": {
    "target": "https://api.target.com",
    "endpoints_tested": 89,
    "tests_performed": 1068,
    "findings_total": 4,
    "findings_critical": 1,
    "findings_high": 2,
    "findings_medium": 1,
    "findings_low": 0
  },
  "findings": [
    {
      "endpoint": "/api/v1/users/45",
      "method": "GET",
      "test_type": "idor",
      "severity": "high",
      "confidence": "high",
      "description": "Low-privilege user accessed 47 different resource IDs...",
      "evidence_curl": "curl -s -H 'Authorization: Bearer ...' 'https://api.target.com/api/v1/users/2'",
      "remediation": "Add server-side ownership checks..."
    }
  ]
}
```

---

## Auth Methods

### Bearer JWT (default)

```yaml
auth:
  method: "bearer_jwt"
  login_endpoint: "/api/auth/login"
  login_method: "POST"
  login_body_template:
    email: "{email}"
    password: "{password}"
  token_location: "response_body"
  token_field: "access_token"         # or nested: "data.auth.token"
  token_header: "Authorization"
  token_prefix: "Bearer "
```

### API Key

```yaml
auth:
  method: "api_key"
  token_header: "X-API-Key"
  token_prefix: ""

users:
  low_priv:
    email: "user@target.com"
    api_key: "user_key_abc123"
    label: "Regular User"
  high_priv:
    email: "admin@target.com"
    api_key: "admin_key_xyz789"
    label: "Administrator"
```

### Cookie Session

```yaml
auth:
  method: "cookie_session"
  login_endpoint: "/auth/login"
  login_method: "POST"
  login_body_template:
    username: "{email}"
    password: "{password}"
```

### OAuth2 Client Credentials

```yaml
auth:
  method: "oauth2"
  token_url: "https://auth.target.com/oauth/token"

users:
  low_priv:
    client_id: "user_client_id"
    client_secret: "user_client_secret"
    scope: "read"
    label: "Regular Client"
  high_priv:
    client_id: "admin_client_id"
    client_secret: "admin_client_secret"
    scope: "read write admin"
    label: "Admin Client"
```

---

## Safety & Scope

- **No exploit payloads.** AuthPulse only changes auth context — never sends SQL injection, XSS, or path traversal.
- **Rate limited.** Default: 5 concurrent requests, 200ms delay. Configurable.
- **Stays in scope.** Only tests endpoints you provide. Never crawls or discovers new paths.
- **Only test systems you own or have written permission to test.**

---

## Folder Structure

```
authpulse/
├── setup.py
├── requirements.txt
├── config.yaml
├── demo-juice-shop.yaml
├── authpulse/
│   ├── cli.py              CLI entrypoint
│   ├── engine.py           Scan orchestration
│   ├── auth/
│   │   ├── authenticator.py  Login flows, token extraction
│   │   └── jwt_utils.py      JWT parsing and test token generation
│   ├── endpoints/
│   │   └── loader.py         Endpoint loading (JSON, text, ParamSpider)
│   ├── tester/
│   │   ├── models.py         ResponseSnapshot, TestResult
│   │   ├── auth_tests.py     Token removal, swap, expiry tests
│   │   ├── idor_tests.py     ID cycling, UUID manipulation
│   │   ├── param_tests.py    Mass assignment, debug params
│   │   └── jwt_tests.py      Role claim injection
│   ├── analyzer/
│   │   └── comparator.py     Response comparison, false positive reduction
│   └── output/
│       ├── terminal.py       Rich terminal display
│       └── json_writer.py    JSON + Markdown report generation
├── endpoints/
│   ├── example.json
│   └── juice-shop-endpoints.json
└── output/
```

---

## License

For authorized security testing only. You are responsible for obtaining proper authorization before testing any system.
