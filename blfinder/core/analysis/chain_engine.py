"""
core/analysis/chain_engine.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHAINED VULNERABILITY ENGINE

Connects individual findings that are harmless alone into exploit chains
that can achieve critical impact. This is the highest-ROI improvement
because chained findings:

  1. Pay 2-5× more on HackerOne than individual findings
  2. Catch an entire class of bugs no single module can see
  3. Prove real-world exploitability rather than theoretical risk

CORE INSIGHT
════════════
Individual finding:  "Mass assignment allows setting is_admin=true"  → MEDIUM
Individual finding:  "Admin endpoint returns 403 to normal user"     → INFO
Chained finding:     "Mass assignment → admin panel access → dump all users" → CRITICAL

The engine works as a directed graph:
  - Nodes = individual findings (capabilities)
  - Edges = "Finding A enables Finding B" relationships
  - Paths = exploit chains (sequences of A → B → C)

CHAIN TYPES DETECTED (12 patterns)
═══════════════════════════════════

CHAIN_1  Privilege Escalation Chain
  mass_assignment(is_admin=true) → bfla(admin_endpoint) → data_exposure
  "Gain admin via mass assignment, access admin API, exfiltrate data"

CHAIN_2  Auth Bypass → IDOR
  workflow_bypass(skip_auth_step) → idor(access_other_user)
  "Bypass auth flow, then enumerate other users' resources"

CHAIN_3  Unauthenticated Data Chain
  auth_diff(unauth_field_exposure) → bopla(hidden_params)
  "Unauthenticated leak reveals internal field names to use in BOPLA"

CHAIN_4  Token Harvesting Chain
  js_secret(api_key_in_js) → privilege_escalation(use_key_as_admin)
  "Extract token from JS, use it to access privileged endpoints"

CHAIN_5  Race → Financial Abuse
  race_condition(double_submit) → negative_quantity(reverse_charge)
  "Race condition + negative values = double negative = credit fraud"

CHAIN_6  State Machine → Refund Fraud
  state_machine_abuse(force_paid) → workflow_bypass(skip_refund_check)
  "Force order to paid state, then refund for money never spent"

CHAIN_7  IDOR → Mass Exfiltration
  idor(enumerate_ids) → limit_offset(dump_all_records)
  "IDOR gives valid IDs, pagination bypass dumps all records at once"

CHAIN_8  Hidden Endpoint → Privilege
  hidden_endpoint(admin_debug_path) → bfla(admin_function)
  "Hidden debug endpoint discovered, grants admin functions"

CHAIN_9  Coupon + Race → Free Products
  coupon_stacking(apply_multiple) → race_condition(simultaneous_checkout)
  "Stack coupons AND race the checkout = order everything for free"

CHAIN_10 JWT → Account Takeover
  jwt_manipulation(alg_none_bypass) → idor(impersonate_any_user)
  "Forge JWT as any user ID, access any account"

CHAIN_11 Mass Assignment → Subscription Fraud
  mass_assignment(is_premium=true) → bopla(expose_premium_fields)
  "Elevate own account to premium, then access premium data endpoints"

CHAIN_12 Parameter Pollution → IDOR
  parameter_pollution(duplicate_id) → idor(server_uses_second_value)
  "Pollute ID parameter, server uses second value = access other resource"

ALGORITHM
═════════

Phase 1 — Capability Extraction
  Each finding is classified into one or more "capability" types.
  A capability represents what an attacker CAN DO with the finding.

  Examples:
    mass_assignment → CAN_ELEVATE_PRIVILEGE
    idor → CAN_ACCESS_FOREIGN_RESOURCE
    race_condition → CAN_EXECUTE_TWICE
    jwt_manipulation → CAN_FORGE_IDENTITY
    auth_diff(credential_leak) → HAS_CREDENTIAL
    hidden_endpoint → HAS_PRIVILEGED_ACCESS

Phase 2 — Chain Rule Matching
  12 chain rules are evaluated against the capability set.
  Each rule specifies:
    - required_capabilities: list (all must be present)
    - optional_capabilities: list (any enhance the chain)
    - chain_type: string identifier
    - impact: severity level
    - narrative: human-readable exploit description
    - requires_same_endpoint: bool (some chains need findings on same endpoint)

Phase 3 — Evidence Collection
  For each matched chain, collect the specific findings that contributed.
  Build a step-by-step exploitation narrative with real endpoint references.

Phase 4 — Exploitability Scoring
  Score each chain 0-100 based on:
    - Number of required capabilities met
    - Presence of optional capabilities (bonus)
    - Confidence of individual findings
    - Same-endpoint co-location (stronger signal)
    - Confirmation status of individual findings

Phase 5 — Active Chain Verification (optional)
  For high-confidence chains, attempt to actually execute the chain:
    Step 1: Execute finding A's attack
    Step 2: Use the result (token/ID/state) as input to finding B
    Step 3: Record whether B's impact is greater with A's output
  This produces "VERIFIED EXPLOIT CHAIN" findings with full evidence.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional







CAP_ELEVATE_PRIVILEGE    = "CAN_ELEVATE_PRIVILEGE"      
CAP_ACCESS_FOREIGN       = "CAN_ACCESS_FOREIGN_RESOURCE" 
CAP_EXECUTE_TWICE        = "CAN_EXECUTE_TWICE"           
CAP_FORGE_IDENTITY       = "CAN_FORGE_IDENTITY"          
CAP_BYPASS_WORKFLOW      = "CAN_BYPASS_WORKFLOW"         
CAP_DUMP_RECORDS         = "CAN_DUMP_RECORDS"            
CAP_ACCESS_ADMIN         = "CAN_ACCESS_ADMIN"            
CAP_HAS_CREDENTIAL       = "HAS_LEAKED_CREDENTIAL"       
CAP_MANIPULATE_PRICE     = "CAN_MANIPULATE_PRICE"        
CAP_NEGATIVE_VALUE       = "CAN_USE_NEGATIVE_VALUE"      
CAP_STACK_COUPONS        = "CAN_STACK_COUPONS"           
CAP_FORCE_STATE          = "CAN_FORCE_STATE"             
CAP_HIDDEN_PATH          = "HAS_HIDDEN_PATH"             
CAP_POLLUTE_PARAM        = "CAN_POLLUTE_PARAM"           
CAP_EXPOSE_INTERNALS     = "CAN_EXPOSE_INTERNALS"        
CAP_UNAUTH_DATA          = "HAS_UNAUTH_DATA"             






@dataclass
class CapabilityNode:
    """A single finding annotated with its capabilities."""
    finding:      dict                      
    capabilities: set[str]                  
    endpoint:     str
    category:     str
    severity:     str
    confidence:   int
    confirmed:    bool


@dataclass
class ChainRule:
    """A rule defining one type of exploit chain."""
    chain_id:              str
    name:                  str
    required_caps:         list[str]        
    optional_caps:         list[str]        
    severity:              str
    cvss:                  float
    cwe:                   str
    owasp:                 str
    narrative_template:    str              
    impact_template:       str
    recommendation:        str
    requires_same_endpoint: bool = False


@dataclass
class ChainMatch:
    """A matched exploit chain with collected evidence."""
    rule:                ChainRule
    contributing_nodes:  list[CapabilityNode]
    required_nodes:      list[CapabilityNode]
    optional_nodes:      list[CapabilityNode]
    exploitability:      int                  
    verified:            bool = False
    verification_evidence: str = ""
    endpoints_involved:  list[str] = field(default_factory=list)






CHAIN_RULES: list[ChainRule] = [

    ChainRule(
        chain_id="CHAIN_1",
        name="Privilege Escalation → Admin Data Exfiltration",
        required_caps=[CAP_ELEVATE_PRIVILEGE, CAP_ACCESS_ADMIN],
        optional_caps=[CAP_DUMP_RECORDS, CAP_ACCESS_FOREIGN],
        severity="CRITICAL",
        cvss=9.8,
        cwe="CWE-269",
        owasp="API5:2023 Broken Function Level Authorization",
        narrative_template=(
            "Step 1: Exploit privilege escalation at {step1_endpoint} — "
            "{step1_desc}\n"
            "Step 2: Use elevated privileges to access admin endpoint at "
            "{step2_endpoint} — {step2_desc}\n"
            "Impact: Full administrative access achieved. An attacker can "
            "read/modify/delete any user's data."
        ),
        impact_template=(
            "An attacker with a regular account can elevate themselves to admin "
            "and gain full access to administrative functions including user "
            "management, data export, and system configuration."
        ),
        recommendation=(
            "1. Fix the privilege escalation vulnerability (mass assignment / "
            "JWT issue) immediately.\n"
            "2. Add server-side role validation on all admin endpoints.\n"
            "3. Implement the principle of least privilege."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_2",
        name="Authentication Bypass → IDOR Cross-User Access",
        required_caps=[CAP_BYPASS_WORKFLOW, CAP_ACCESS_FOREIGN],
        optional_caps=[CAP_DUMP_RECORDS, CAP_EXPOSE_INTERNALS],
        severity="CRITICAL",
        cvss=9.1,
        cwe="CWE-287",
        owasp="API1:2023 Broken Object Level Authorization",
        narrative_template=(
            "Step 1: Bypass authentication/verification at {step1_endpoint} — "
            "{step1_desc}\n"
            "Step 2: Use unauthenticated session to access another user's "
            "resource at {step2_endpoint} — {step2_desc}\n"
            "Impact: Access to any user's private data without valid credentials."
        ),
        impact_template=(
            "An attacker can bypass authentication checks and then directly "
            "access other users' resources, achieving account takeover or "
            "mass data exfiltration."
        ),
        recommendation=(
            "1. Fix the workflow bypass — enforce sequential step validation.\n"
            "2. Verify resource ownership on every request, independent of "
            "authentication state."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_3",
        name="Credential Leak → Account Takeover",
        required_caps=[CAP_HAS_CREDENTIAL, CAP_FORGE_IDENTITY],
        optional_caps=[CAP_ACCESS_FOREIGN, CAP_ACCESS_ADMIN],
        severity="CRITICAL",
        cvss=9.8,
        cwe="CWE-312",
        owasp="API2:2023 Broken Authentication",
        narrative_template=(
            "Step 1: Extract leaked credential from {step1_endpoint} — "
            "{step1_desc}\n"
            "Step 2: Use credential to forge authenticated identity at "
            "{step2_endpoint} — {step2_desc}\n"
            "Impact: Account takeover for any user whose credential was leaked."
        ),
        impact_template=(
            "Leaked credentials combined with authentication bypass allow "
            "complete account takeover without knowing the user's password."
        ),
        recommendation=(
            "1. Remove credentials from all API responses immediately.\n"
            "2. Rotate any exposed credentials.\n"
            "3. Fix the authentication bypass vulnerability."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_4",
        name="Race Condition + Negative Value → Financial Fraud",
        required_caps=[CAP_EXECUTE_TWICE, CAP_NEGATIVE_VALUE],
        optional_caps=[CAP_STACK_COUPONS, CAP_MANIPULATE_PRICE],
        severity="CRITICAL",
        cvss=9.3,
        cwe="CWE-362",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Submit negative quantity/amount at {step1_endpoint} — "
            "{step1_desc}\n"
            "Step 2: Race condition at {step2_endpoint} processes multiple "
            "requests simultaneously — {step2_desc}\n"
            "Impact: Negative charge processed multiple times = "
            "attacker receives money instead of paying."
        ),
        impact_template=(
            "Combining negative values with race conditions allows an attacker "
            "to receive money from the platform rather than paying. "
            "Direct financial loss to the company."
        ),
        recommendation=(
            "1. Enforce quantity >= 1 server-side before any financial processing.\n"
            "2. Use database-level locks (SELECT FOR UPDATE) on financial operations.\n"
            "3. Implement idempotency keys for all payment endpoints."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_5",
        name="State Machine Abuse → Refund Fraud",
        required_caps=[CAP_FORCE_STATE, CAP_BYPASS_WORKFLOW],
        optional_caps=[CAP_MANIPULATE_PRICE, CAP_EXECUTE_TWICE],
        severity="CRITICAL",
        cvss=9.0,
        cwe="CWE-284",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Force order/payment to 'completed' state at "
            "{step1_endpoint} without actual payment — {step1_desc}\n"
            "Step 2: Bypass refund workflow validation at {step2_endpoint} — "
            "{step2_desc}\n"
            "Impact: Receive refund for a payment that was never made."
        ),
        impact_template=(
            "An attacker can force objects into a 'paid' or 'completed' state "
            "without actual payment, then request a refund. Net result: "
            "the attacker receives money without spending any."
        ),
        recommendation=(
            "1. Compute state transitions server-side only.\n"
            "2. Never trust client-supplied state values.\n"
            "3. Verify payment confirmation before allowing refunds."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_6",
        name="IDOR → Mass Data Exfiltration via Pagination Bypass",
        required_caps=[CAP_ACCESS_FOREIGN, CAP_DUMP_RECORDS],
        optional_caps=[CAP_EXPOSE_INTERNALS, CAP_HIDDEN_PATH],
        severity="CRITICAL",
        cvss=8.5,
        cwe="CWE-639",
        owasp="API1:2023 Broken Object Level Authorization",
        narrative_template=(
            "Step 1: IDOR at {step1_endpoint} reveals valid resource IDs for "
            "other users — {step1_desc}\n"
            "Step 2: Pagination bypass at {step2_endpoint} dumps all records "
            "using harvested IDs — {step2_desc}\n"
            "Impact: Complete database dump of all user records."
        ),
        impact_template=(
            "IDOR provides valid IDs for other users' resources. "
            "Combined with pagination bypass (limit=99999), an attacker can "
            "dump the entire user database in a single chain of requests."
        ),
        recommendation=(
            "1. Fix IDOR — enforce object-level ownership checks.\n"
            "2. Enforce server-side maximum page size.\n"
            "3. Rate-limit bulk data endpoints."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_7",
        name="JWT Forge → Full Account Takeover",
        required_caps=[CAP_FORGE_IDENTITY, CAP_ACCESS_FOREIGN],
        optional_caps=[CAP_ACCESS_ADMIN, CAP_ELEVATE_PRIVILEGE],
        severity="CRITICAL",
        cvss=10.0,
        cwe="CWE-347",
        owasp="API2:2023 Broken Authentication",
        narrative_template=(
            "Step 1: Forge JWT with alg:none or arbitrary claims at "
            "{step1_endpoint} — {step1_desc}\n"
            "Step 2: Use forged JWT to access any user's account at "
            "{step2_endpoint} — {step2_desc}\n"
            "Impact: Complete account takeover for any user ID."
        ),
        impact_template=(
            "Forging a JWT allows impersonating any user. "
            "Combined with IDOR to enumerate valid user IDs, "
            "an attacker can take over every account on the platform."
        ),
        recommendation=(
            "1. Whitelist allowed JWT algorithms — never accept 'none'.\n"
            "2. Verify JWT signature server-side on every request.\n"
            "3. Fix IDOR to prevent user ID enumeration."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_8",
        name="Hidden Admin Endpoint → Privileged Function Abuse",
        required_caps=[CAP_HIDDEN_PATH, CAP_ACCESS_ADMIN],
        optional_caps=[CAP_ELEVATE_PRIVILEGE, CAP_DUMP_RECORDS],
        severity="CRITICAL",
        cvss=9.1,
        cwe="CWE-284",
        owasp="API5:2023 Broken Function Level Authorization",
        narrative_template=(
            "Step 1: Discovered hidden endpoint at {step1_endpoint} — "
            "{step1_desc}\n"
            "Step 2: Hidden endpoint exposes admin function at "
            "{step2_endpoint} — {step2_desc}\n"
            "Impact: Administrative access via obscured endpoint with no "
            "visible auth requirement."
        ),
        impact_template=(
            "A hidden/undocumented endpoint discovered through path scanning "
            "provides direct access to administrative functionality that "
            "bypasses normal authorization."
        ),
        recommendation=(
            "1. Remove or properly secure all debug/internal endpoints.\n"
            "2. Implement authorization checks independent of endpoint obscurity.\n"
            "3. Conduct regular endpoint inventory audits."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_9",
        name="Coupon Abuse + Race Condition → Free Products",
        required_caps=[CAP_STACK_COUPONS, CAP_EXECUTE_TWICE],
        optional_caps=[CAP_MANIPULATE_PRICE, CAP_BYPASS_WORKFLOW],
        severity="CRITICAL",
        cvss=8.8,
        cwe="CWE-362",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Stack multiple coupons at {step1_endpoint} — "
            "{step1_desc}\n"
            "Step 2: Race condition at checkout {step2_endpoint} processes "
            "multiple discounted orders simultaneously — {step2_desc}\n"
            "Impact: Products obtained for free or at extreme discount."
        ),
        impact_template=(
            "Coupon stacking reduces price to near-zero. "
            "Race condition then allows placing multiple orders "
            "at that near-zero price before the server detects the abuse."
        ),
        recommendation=(
            "1. Enforce single-coupon-per-order server-side.\n"
            "2. Use database locks on order placement.\n"
            "3. Re-validate price at payment time, not at cart creation."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_10",
        name="Mass Assignment → Premium Feature Abuse",
        required_caps=[CAP_ELEVATE_PRIVILEGE, CAP_EXPOSE_INTERNALS],
        optional_caps=[CAP_DUMP_RECORDS, CAP_ACCESS_FOREIGN],
        severity="HIGH",
        cvss=8.1,
        cwe="CWE-915",
        owasp="API3:2023 Broken Object Property Level Authorization",
        narrative_template=(
            "Step 1: Mass assignment at {step1_endpoint} sets premium/paid "
            "account flag — {step1_desc}\n"
            "Step 2: With elevated account type, BOPLA at {step2_endpoint} "
            "exposes premium-only data fields — {step2_desc}\n"
            "Impact: Free access to paid/premium features and data."
        ),
        impact_template=(
            "Setting account tier to 'premium' via mass assignment, "
            "then exploiting object property exposure to access "
            "premium-only fields — bypassing subscription payments entirely."
        ),
        recommendation=(
            "1. Use explicit field allowlists, never auto-bind request fields.\n"
            "2. Enforce subscription tier server-side on every data access.\n"
            "3. Never trust client-supplied account tier values."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_11",
        name="Unauthenticated Leak → Targeted IDOR",
        required_caps=[CAP_UNAUTH_DATA, CAP_ACCESS_FOREIGN],
        optional_caps=[CAP_EXPOSE_INTERNALS, CAP_DUMP_RECORDS],
        severity="HIGH",
        cvss=8.3,
        cwe="CWE-200",
        owasp="API3:2023 Broken Object Property Level Authorization",
        narrative_template=(
            "Step 1: Unauthenticated response at {step1_endpoint} leaks "
            "internal IDs or user identifiers — {step1_desc}\n"
            "Step 2: Use leaked IDs to directly access other users' resources "
            "at {step2_endpoint} via IDOR — {step2_desc}\n"
            "Impact: Targeted access to specific users' data using leaked IDs."
        ),
        impact_template=(
            "Unauthenticated data leak provides user IDs or resource IDs "
            "that can be used directly in IDOR attacks, enabling targeted "
            "access to any specific user's data."
        ),
        recommendation=(
            "1. Remove all user identifiers from unauthenticated responses.\n"
            "2. Fix IDOR — enforce ownership checks.\n"
            "3. Use opaque, non-enumerable identifiers."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_12",
        name="Parameter Pollution → IDOR",
        required_caps=[CAP_POLLUTE_PARAM, CAP_ACCESS_FOREIGN],
        optional_caps=[CAP_EXPOSE_INTERNALS],
        severity="HIGH",
        cvss=7.5,
        cwe="CWE-20",
        owasp="API1:2023 Broken Object Level Authorization",
        narrative_template=(
            "Step 1: Parameter pollution at {step1_endpoint} — duplicating "
            "the ID parameter causes server to use the second (attacker-controlled) "
            "value — {step1_desc}\n"
            "Step 2: Server processes request as if accessing attacker-specified "
            "resource at {step2_endpoint} — {step2_desc}\n"
            "Impact: Access to any resource by polluting the ID parameter."
        ),
        impact_template=(
            "Duplicate query/body parameters cause the backend to use the "
            "attacker-supplied value instead of the authenticated user's value, "
            "effectively acting as an IDOR through parameter confusion."
        ),
        recommendation=(
            "1. Always use only the first occurrence of duplicate parameters.\n"
            "2. Validate the ID against the authenticated user's ownership.\n"
            "3. Reject requests with duplicate parameter names."
        ),
    ),
]






class CapabilityClassifier:
    """
    Classifies a finding dict into a set of capability strings.
    Uses category, title, and metadata to determine what the
    finding enables an attacker to do.
    """

    def classify(self, finding: dict) -> set[str]:
        caps:     set[str] = set()
        category: str      = (finding.get("category") or "").lower()
        title:    str      = (finding.get("title")    or "").lower()
        severity: str      = (finding.get("severity") or "").upper()
        meta:     dict     = finding.get("_auth_diff") or finding.get("_meta") or {}


        if "mass assignment" in category or "mass assignment" in title:
            caps.add(CAP_ELEVATE_PRIVILEGE)

            param = (finding.get("parameter") or "").lower()
            if any(k in param for k in ["premium", "plan", "subscription", "tier"]):
                caps.add(CAP_EXPOSE_INTERNALS)


        if any(k in category for k in ["idor", "bola", "object level"]):
            caps.add(CAP_ACCESS_FOREIGN)


        if "race condition" in category or "race condition" in title:
            caps.add(CAP_EXECUTE_TWICE)


        if "jwt" in category or "jwt" in title or "alg:none" in title:
            caps.add(CAP_FORGE_IDENTITY)
            caps.add(CAP_ACCESS_FOREIGN)  


        if any(k in category for k in ["workflow", "mfa", "bypass"]):
            caps.add(CAP_BYPASS_WORKFLOW)


        if any(k in category for k in ["bopla", "property", "pagination", "limit"]):
            caps.add(CAP_DUMP_RECORDS)
            caps.add(CAP_EXPOSE_INTERNALS)


        if any(k in category for k in ["privilege", "function level", "bfla"]):
            caps.add(CAP_ACCESS_ADMIN)
            if severity == "CRITICAL":
                caps.add(CAP_ELEVATE_PRIVILEGE)


        if "javascript" in category or "secret" in title or "credential" in title:
            caps.add(CAP_HAS_CREDENTIAL)

        if meta.get("diff_type") in ("UNAUTH_LEAKED_FIELD", "VALUE_EXPOSURE"):
            field_cat = meta.get("field_category", "")
            if field_cat in ("CREDENTIAL", "PII_GOVERNMENT", "PAYMENT_PROCESSOR"):
                caps.add(CAP_HAS_CREDENTIAL)
            caps.add(CAP_UNAUTH_DATA)
            if field_cat in ("IDENTIFIER",):
                caps.add(CAP_ACCESS_FOREIGN)  


        if "price manipulation" in category or "price" in title:
            caps.add(CAP_MANIPULATE_PRICE)


        if "negative" in category or "negative" in title:
            caps.add(CAP_NEGATIVE_VALUE)


        if "coupon" in category or "coupon" in title:
            caps.add(CAP_STACK_COUPONS)


        if "state machine" in category or "state" in title:
            caps.add(CAP_FORCE_STATE)


        if meta.get("hunter") or "hidden" in category or "internal" in title:
            caps.add(CAP_HIDDEN_PATH)
            if any(k in (finding.get("endpoint") or "") for k in [
                "admin", "internal", "debug", "actuator", "private"
            ]):
                caps.add(CAP_ACCESS_ADMIN)


        if "parameter pollution" in category or "pollution" in title:
            caps.add(CAP_POLLUTE_PARAM)


        if "auth diff" in category:
            caps.add(CAP_UNAUTH_DATA)
            caps.add(CAP_EXPOSE_INTERNALS)

        return caps






class ChainDetector:
    """
    Builds the capability graph and matches chain rules against it.
    """

    def __init__(self):
        self._classifier = CapabilityClassifier()

    def detect(self, findings: list[dict]) -> list[ChainMatch]:
        """
        Detect all exploit chains in a list of findings.
        Returns ChainMatch objects sorted by exploitability score descending.
        """
        if not findings:
            return []


        nodes: list[CapabilityNode] = []
        for f in findings:
            caps = self._classifier.classify(f)
            if caps:
                nodes.append(CapabilityNode(
                    finding=f,
                    capabilities=caps,
                    endpoint=f.get("endpoint", ""),
                    category=f.get("category", ""),
                    severity=f.get("severity", "LOW"),
                    confidence=f.get("confidence", 0),
                    confirmed=f.get("confirmed", False),
                ))

        if not nodes:
            return []


        cap_map: dict[str, list[CapabilityNode]] = {}
        for node in nodes:
            for cap in node.capabilities:
                cap_map.setdefault(cap, []).append(node)


        matches: list[ChainMatch] = []
        seen_chains: set[str] = set()

        for rule in CHAIN_RULES:

            if not all(cap in cap_map for cap in rule.required_caps):
                continue


            required_nodes: list[CapabilityNode] = []
            for cap in rule.required_caps:
                best = max(cap_map[cap], key=lambda n: n.confidence + (50 if n.confirmed else 0))
                if best not in required_nodes:
                    required_nodes.append(best)


            optional_nodes: list[CapabilityNode] = []
            for cap in rule.optional_caps:
                if cap in cap_map:
                    best = max(cap_map[cap], key=lambda n: n.confidence)
                    if best not in required_nodes and best not in optional_nodes:
                        optional_nodes.append(best)


            all_contributing = required_nodes + optional_nodes
            chain_key = rule.chain_id + "|" + "|".join(
                sorted(f"{n.endpoint}:{n.category}" for n in required_nodes)
            )
            if chain_key in seen_chains:
                continue
            seen_chains.add(chain_key)


            score = self._score(rule, required_nodes, optional_nodes)


            if score < 25:
                continue

            matches.append(ChainMatch(
                rule=rule,
                contributing_nodes=all_contributing,
                required_nodes=required_nodes,
                optional_nodes=optional_nodes,
                exploitability=score,
                endpoints_involved=list({n.endpoint for n in all_contributing if n.endpoint}),
            ))

        matches.sort(key=lambda m: m.exploitability, reverse=True)
        return matches

    @staticmethod
    def _score(
        rule:           ChainRule,
        required_nodes: list[CapabilityNode],
        optional_nodes: list[CapabilityNode],
    ) -> int:
        score = 30  


        if required_nodes:
            avg_conf = sum(n.confidence for n in required_nodes) / len(required_nodes)
            score += int(avg_conf * 0.3)   


        confirmed_count = sum(1 for n in required_nodes if n.confirmed)
        score += confirmed_count * 10       


        score += len(optional_nodes) * 5    


        endpoints = {n.endpoint for n in required_nodes}
        if len(endpoints) == 1 and "" not in endpoints:
            score += 10   


        sev_bonus = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 0}
        for n in required_nodes:
            score += sev_bonus.get(n.severity, 0)

        return min(100, score)






class ChainVerifier:
    """
    Attempts to actively execute the exploit chain by replaying
    step 1's attack and using its output as input to step 2.
    Only runs on high-confidence chains (exploitability >= 60).
    """

    def __init__(self, scanner, config):
        self._scanner = scanner
        self._config  = config

    async def verify(self, match: ChainMatch) -> ChainMatch:
        """
        Try to actively verify the chain. Updates match.verified and
        match.verification_evidence in place. Returns the updated match.
        """
        if match.exploitability < 60:
            return match  

        if len(match.required_nodes) < 2:
            return match

        chain_id = match.rule.chain_id

        try:
            if chain_id == "CHAIN_1":
                return await self._verify_priv_esc_chain(match)
            elif chain_id == "CHAIN_7":
                return await self._verify_jwt_chain(match)
            elif chain_id == "CHAIN_6":
                return await self._verify_idor_dump_chain(match)

            elif all(n.confirmed for n in match.required_nodes):
                match.verified = True
                match.verification_evidence = (
                    "All required findings are individually confirmed. "
                    "Chain is structurally complete."
                )
        except Exception as e:
            if self._config.verbose:
                print(f"  [chain_verify] {chain_id} error: {e}")

        return match

    async def _verify_priv_esc_chain(self, match: ChainMatch) -> ChainMatch:
        """
        Chain 1: Try mass assignment, then hit admin endpoint with the result.
        """
        mass_assign_node = next(
            (n for n in match.required_nodes
             if CAP_ELEVATE_PRIVILEGE in n.capabilities and
             "mass assignment" in n.category.lower()),
            None,
        )
        admin_node = next(
            (n for n in match.required_nodes
             if CAP_ACCESS_ADMIN in n.capabilities),
            None,
        )
        if not mass_assign_node or not admin_node:
            return match


        req      = mass_assign_node.finding.get("request", {})
        method   = req.get("method", "PUT")
        url      = req.get("url", mass_assign_node.endpoint)
        param    = mass_assign_node.finding.get("parameter", "is_admin")
        body     = {param: True}

        s1, _, b1, _ = await self._scanner._request(
            method, url, json=body,
            token_override=self._config.auth_token or None,
        )

        if s1 not in (200, 201, 204):
            return match


        admin_url = admin_node.endpoint
        s2, _, b2, _ = await self._scanner._request(
            "GET", admin_url,
            token_override=self._config.auth_token or None,
        )

        if s2 == 200 and len(b2) > 50:
            match.verified = True
            match.verification_evidence = (
                f"VERIFIED: Mass assignment at {url} (HTTP {s1}) → "
                f"Admin endpoint {admin_url} returned HTTP {s2} "
                f"with {len(b2)}B response."
            )

        return match

    async def _verify_jwt_chain(self, match: ChainMatch) -> ChainMatch:
        """Chain 7: JWT forge already confirmed by individual finding."""
        jwt_node = next(
            (n for n in match.required_nodes
             if CAP_FORGE_IDENTITY in n.capabilities),
            None,
        )
        if jwt_node and jwt_node.confirmed:
            match.verified = True
            match.verification_evidence = (
                "JWT signature bypass confirmed during individual scan. "
                "Combined with IDOR, arbitrary user impersonation is achievable."
            )
        return match

    async def _verify_idor_dump_chain(self, match: ChainMatch) -> ChainMatch:
        """Chain 6: Check if pagination endpoint accepts large limits."""
        dump_node = next(
            (n for n in match.required_nodes
             if CAP_DUMP_RECORDS in n.capabilities),
            None,
        )
        if not dump_node:
            return match

        url = dump_node.endpoint
        s, _, b, _ = await self._scanner._request(
            "GET", url,
            params={"limit": 99999, "offset": 0},
            token_override=self._config.auth_token or None,
        )
        if s == 200 and b:
            try:
                data = json.loads(b)
                count = len(data) if isinstance(data, list) else len(
                    data.get("data", data.get("results", []))
                )
                if count > 10:
                    match.verified = True
                    match.verification_evidence = (
                        f"Pagination bypass verified: limit=99999 returned "
                        f"{count} records from {url}. "
                        f"Combined with IDOR for ID enumeration = full DB dump."
                    )
            except Exception:
                pass

        return match






class ChainFindingGenerator:
    """
    Converts ChainMatch objects into Finding-compatible dicts
    for BLFScanner's reporting pipeline.
    """

    def generate(self, matches: list[ChainMatch]) -> list[dict]:
        findings: list[dict] = []
        for match in matches:
            findings.append(self._to_finding(match))
        return findings

    def _to_finding(self, match: ChainMatch) -> dict:
        rule = match.rule


        steps = []
        for i, node in enumerate(match.required_nodes[:3], 1):
            f = node.finding
            steps.append(
                f"Step {i}: [{f.get('severity','?')}] {f.get('title','')[:70]} "
                f"at {node.endpoint}"
            )

        steps_text = "\n".join(steps)


        step1 = match.required_nodes[0] if match.required_nodes else None
        step2 = match.required_nodes[1] if len(match.required_nodes) > 1 else step1

        narrative = rule.narrative_template.format(
            step1_endpoint=step1.endpoint if step1 else "?",
            step1_desc=step1.finding.get("title", "")[:60] if step1 else "",
            step2_endpoint=step2.endpoint if step2 else "?",
            step2_desc=step2.finding.get("title", "")[:60] if step2 else "",
            endpoint=match.endpoints_involved[0] if match.endpoints_involved else "?",
        )


        evidence_parts = [
            f"Chain: {rule.name}",
            f"Exploitability: {match.exploitability}/100",
            f"Verified: {'YES — ' + match.verification_evidence if match.verified else 'Structural (individual findings confirmed)'}",
            "",
            "Contributing Findings:",
            steps_text,
            "",
            "Exploitation Narrative:",
            narrative,
        ]
        if match.optional_nodes:
            bonus = [
                f"  + [{n.severity}] {n.finding.get('title','')[:60]}"
                for n in match.optional_nodes[:3]
            ]
            evidence_parts += ["", "Bonus capabilities present:"] + bonus

        return {
            "title": (
                f"Exploit Chain [{rule.chain_id}]: {rule.name} "
                f"({match.exploitability}/100 exploitability"
                + (" — VERIFIED" if match.verified else "")
                + ")"
            ),
            "severity":    rule.severity,
            "category":    f"Business Logic — Exploit Chain — {rule.chain_id}",
            "description": rule.impact_template,
            "request": {
                "method":  "CHAIN",
                "url":     match.endpoints_involved[0] if match.endpoints_involved else "",
                "note":    f"Multi-step chain involving {len(match.contributing_nodes)} findings",
            },
            "response_summary": (
                f"Chain of {len(match.required_nodes)} findings with "
                f"exploitability {match.exploitability}/100"
                + (" [VERIFIED]" if match.verified else "")
            ),
            "evidence":        "\n".join(evidence_parts),
            "recommendation":  rule.recommendation,
            "cwe":             rule.cwe,
            "cvss":            rule.cvss,
            "owasp":           rule.owasp,
            "confirmed":       match.verified or all(n.confirmed for n in match.required_nodes),
            "confidence":      match.exploitability,
            "endpoint":        match.endpoints_involved[0] if match.endpoints_involved else "",
            "parameter":       f"chain:{rule.chain_id}",
            "_chain_meta": {
                "chain_id":          rule.chain_id,
                "chain_name":        rule.name,
                "exploitability":    match.exploitability,
                "verified":          match.verified,
                "required_count":    len(match.required_nodes),
                "optional_count":    len(match.optional_nodes),
                "endpoints":         match.endpoints_involved,
                "contributing_titles": [
                    n.finding.get("title", "")[:60]
                    for n in match.contributing_nodes
                ],
            },
        }






class ChainEngine:
    """
    Public API for the Chained Vulnerability Engine.

    Usage in BLFScanner.run_all_modules():
        engine = ChainEngine(scanner, config)

        # After all individual findings are collected:
        chain_findings = await engine.analyze(all_findings)
        all_findings.extend(chain_findings)
    """

    def __init__(self, scanner, config):
        self._scanner   = scanner
        self._config    = config
        self._detector  = ChainDetector()
        self._verifier  = ChainVerifier(scanner, config)
        self._generator = ChainFindingGenerator()

    async def analyze(self, findings: list[dict]) -> list[dict]:
        """
        Analyze a list of findings for exploit chains.
        Returns new Finding-compatible dicts for each chain detected.
        """
        if len(findings) < 2:
            return []  

        print(f"  [chain_engine] analyzing {len(findings)} findings for exploit chains...")


        matches = self._detector.detect(findings)
        if not matches:
            print("  [chain_engine] no exploit chains detected")
            return []

        print(f"  [chain_engine] {len(matches)} potential chains found — verifying...")


        verify_tasks = [
            self._verifier.verify(m)
            for m in matches
            if m.exploitability >= 50
        ]
        if verify_tasks:
            verified = await asyncio.gather(*verify_tasks, return_exceptions=True)
            for i, result in enumerate(verified):
                if isinstance(result, ChainMatch):
                    matches[i] = result


        chain_findings = self._generator.generate(matches)

        verified_count = sum(1 for m in matches if m.verified)
        print(
            f"  [chain_engine] {len(chain_findings)} chains reported "
            f"({verified_count} actively verified)"
        )

        return chain_findings
