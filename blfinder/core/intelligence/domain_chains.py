"""
core/intelligence/domain_chains.py

Fintech and Spotify domain-specific exploit chains.
Extends chain_engine.py by adding new capability constants,
new ChainRule entries, and new CapabilityClassifier logic
without modifying the existing chain_engine.py file.

Call DomainChainEngine.register() once at startup to register everything.

FIX CHANGELOG:
  BUG-2  : Import path corrected from `core.chain_engine` to
            `core.analysis.chain_engine` — matches the path used everywhere
            else in the codebase (scanner_integration.py, etc.).  The old
            path caused an ImportError that was swallowed by a bare
            try/except, meaning none of the fintech/streaming chain rules
            were ever registered.

  BUG-11 : DomainChainEngine.register() is now thread-safe.  The previous
            class-level `_registered = False` flag was read and set without
            a lock.  Two concurrent callers could both read False and register
            rules twice, causing duplicate CHAIN_RULES entries.  Fixed with
            threading.Lock().

  BUG-12 : extend_capability_classifier() now guards against double-patching
            using its own flag (_classifier_extended).  Previously, if
            register() was called twice (due to the race above), the
            classifier was patched twice — causing exponential capability
            sets and duplicate chain-rule hits.
"""

from __future__ import annotations

import threading

# FIX (BUG-2): corrected import path from `core.chain_engine` to
# `core.analysis.chain_engine`.  The codebase consistently uses the latter;
# the wrong path caused a silent ImportError that killed all chain rules.
from core.analysis.chain_engine import (
    CHAIN_RULES,
    ChainRule,
    CapabilityClassifier,
    CAP_ELEVATE_PRIVILEGE,
    CAP_ACCESS_FOREIGN,
    CAP_EXECUTE_TWICE,
    CAP_FORGE_IDENTITY,
    CAP_BYPASS_WORKFLOW,
    CAP_DUMP_RECORDS,
    CAP_ACCESS_ADMIN,
    CAP_HAS_CREDENTIAL,
    CAP_MANIPULATE_PRICE,
    CAP_NEGATIVE_VALUE,
    CAP_STACK_COUPONS,
    CAP_FORCE_STATE,
    CAP_HIDDEN_PATH,
    CAP_POLLUTE_PARAM,
    CAP_EXPOSE_INTERNALS,
    CAP_UNAUTH_DATA,
)


# ─────────────────────────────────────────────────────────────────────────────
# New capability constants for domain modules
# ─────────────────────────────────────────────────────────────────────────────

CAP_NEGATIVE_AMOUNT    = "CAN_USE_NEGATIVE_AMOUNT"
CAP_CURRENCY_CONFUSE   = "CAN_CONFUSE_CURRENCY"
CAP_REPLAY_IDEM        = "CAN_REPLAY_IDEMPOTENCY"
CAP_OVERFLOW_REFUND    = "CAN_OVERFLOW_REFUND"
CAP_FORGE_WEBHOOK      = "CAN_FORGE_WEBHOOK"
CAP_BYPASS_FEE         = "CAN_BYPASS_FEE"
CAP_BYPASS_KYC         = "CAN_BYPASS_KYC"
CAP_ACCESS_TRANSFER    = "CAN_ACCESS_FOREIGN_TRANSFER"
CAP_ACCESS_PREMIUM     = "CAN_ACCESS_PREMIUM_CONTENT"
CAP_INFLATE_STREAMS    = "CAN_INFLATE_STREAM_COUNT"
CAP_REPLAY_DOWNLOAD    = "CAN_REPLAY_DOWNLOAD_TOKEN"
CAP_BYPASS_DEVICE_CAP  = "CAN_BYPASS_DEVICE_LIMIT"
CAP_ACCESS_RESOURCE    = "CAN_ACCESS_FOREIGN_RESOURCE_STREAMING"


# ─────────────────────────────────────────────────────────────────────────────
# Domain chain rules
# ─────────────────────────────────────────────────────────────────────────────

_DOMAIN_CHAIN_RULES: list[ChainRule] = [

    ChainRule(
        chain_id="CHAIN_FINTECH_1",
        name="Negative Amount + Race Condition → Financial Fraud",
        required_caps=[CAP_NEGATIVE_AMOUNT, CAP_EXECUTE_TWICE],
        optional_caps=[CAP_REPLAY_IDEM, CAP_BYPASS_FEE],
        severity="CRITICAL",
        cvss=9.8,
        cwe="CWE-362",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Submit negative amount at {step1_endpoint} — {step1_desc}\n"
            "Step 2: Race condition at {step2_endpoint} processes multiple "
            "concurrent requests — {step2_desc}\n"
            "Impact: Attacker receives money instead of paying, multiplied by "
            "successful race condition attempts."
        ),
        impact_template=(
            "Negative amount accepted combined with a race condition allows "
            "an attacker to receive money from the platform. Each successful "
            "race doubles the fraudulent credit. Direct and immediate financial "
            "loss with no user interaction required."
        ),
        recommendation=(
            "1. Reject negative amounts at the API gateway before any processing.\n"
            "2. Use SELECT FOR UPDATE or Redis SETNX on all financial operations.\n"
            "3. Implement idempotency keys on every payment endpoint.\n"
            "4. Add real-time anomaly detection for negative-value transactions."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_FINTECH_2",
        name="Currency Confusion → Refund Overflow → Double Profit",
        required_caps=[CAP_CURRENCY_CONFUSE, CAP_OVERFLOW_REFUND],
        optional_caps=[CAP_REPLAY_IDEM, CAP_NEGATIVE_AMOUNT],
        severity="CRITICAL",
        cvss=9.5,
        cwe="CWE-20",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Currency confusion at {step1_endpoint} — submit amount "
            "in low-value currency (e.g. JPY) but have server process as "
            "high-value (USD): {step1_desc}\n"
            "Step 2: Refund overflow at {step2_endpoint} — refund the "
            "inflated amount: {step2_desc}\n"
            "Impact: Pay $1 USD, get credited $100 JPY converted to $1 USD, "
            "then refund $100 USD. Net gain: $99 per exploit."
        ),
        impact_template=(
            "Currency confusion inflates the transaction amount on the server. "
            "Combined with refund overflow (no cap on refund vs original), "
            "an attacker can systematically extract money from the platform "
            "at scale."
        ),
        recommendation=(
            "1. Validate currency_code against a server-side whitelist.\n"
            "2. Cap refund amounts to the original charge amount.\n"
            "3. Store original currency and amount at charge time, validate "
            "refunds against stored values only.\n"
            "4. Alert on refund > original charge."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_FINTECH_3",
        name="Idempotency Replay → Refund Overflow → Unlimited Withdrawal",
        required_caps=[CAP_REPLAY_IDEM, CAP_OVERFLOW_REFUND],
        optional_caps=[CAP_EXECUTE_TWICE, CAP_NEGATIVE_AMOUNT],
        severity="CRITICAL",
        cvss=9.3,
        cwe="CWE-362",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Replay idempotency key at {step1_endpoint} to create "
            "duplicate transactions — {step1_desc}\n"
            "Step 2: Refund overflow at {step2_endpoint} allows refunding "
            "more than each transaction's original value — {step2_desc}\n"
            "Impact: Create N duplicate charges, refund each for > original. "
            "Net: attacker profits per cycle."
        ),
        impact_template=(
            "Idempotency key replay creates duplicate transactions. Combined "
            "with uncapped refunds, each duplicate can be refunded for more "
            "than its original value, creating an unlimited withdrawal loop."
        ),
        recommendation=(
            "1. Enforce idempotency key deduplication scoped to the user.\n"
            "2. Store original transaction amount and cap refunds to that value.\n"
            "3. Rate-limit refund requests per user per time window.\n"
            "4. Audit all refunds exceeding 95% of original charge."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_FINTECH_4",
        name="Webhook Forgery → Order Fulfilment Without Payment",
        required_caps=[CAP_FORGE_WEBHOOK, CAP_BYPASS_WORKFLOW],
        optional_caps=[CAP_ACCESS_FOREIGN, CAP_FORCE_STATE],
        severity="CRITICAL",
        cvss=9.8,
        cwe="CWE-345",
        owasp="API2:2023 Broken Authentication",
        narrative_template=(
            "Step 1: Forge webhook payment.completed event at "
            "{step1_endpoint} — {step1_desc}\n"
            "Step 2: Workflow bypass allows order confirmation without "
            "actual payment verification at {step2_endpoint} — {step2_desc}\n"
            "Impact: Orders fulfilled for free. Attacker obtains goods or "
            "services without any payment."
        ),
        impact_template=(
            "A forged webhook event triggers order fulfilment without "
            "real payment. The platform delivers goods/services and records "
            "a completed payment that never occurred. Scales to any order size."
        ),
        recommendation=(
            "1. Validate webhook signatures using HMAC-SHA256 before "
            "any business logic executes.\n"
            "2. Verify payment status directly with the payment provider "
            "API rather than trusting webhook events alone.\n"
            "3. Implement a secondary confirmation step for high-value orders."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_FINTECH_5",
        name="KYC Bypass → High-Value Transfer Without Verification",
        required_caps=[CAP_BYPASS_KYC, CAP_ACCESS_TRANSFER],
        optional_caps=[CAP_NEGATIVE_AMOUNT, CAP_CURRENCY_CONFUSE],
        severity="CRITICAL",
        cvss=9.1,
        cwe="CWE-285",
        owasp="API5:2023 Broken Function Level Authorization",
        narrative_template=(
            "Step 1: KYC/SCA bypass at {step1_endpoint} — skip identity "
            "verification step — {step1_desc}\n"
            "Step 2: Transfer IDOR at {step2_endpoint} — access or initiate "
            "transfers belonging to other accounts — {step2_desc}\n"
            "Impact: Attacker moves funds across accounts without triggering "
            "identity verification, evading AML controls."
        ),
        impact_template=(
            "KYC bypass allows unverified users to access financial operations "
            "requiring verification. Combined with transfer IDOR, this enables "
            "unauthorised high-value transfers and potential money laundering "
            "without regulatory controls firing."
        ),
        recommendation=(
            "1. Enforce KYC status check on every regulated financial endpoint "
            "server-side, not just at account creation.\n"
            "2. Validate transfer ownership with a hard check on the "
            "authenticated user's account ID.\n"
            "3. Log and alert on any attempt to access transfer endpoints "
            "before KYC completion."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_FINTECH_6",
        name="Fee Bypass + Negative Amount → Profit From Transactions",
        required_caps=[CAP_BYPASS_FEE, CAP_NEGATIVE_AMOUNT],
        optional_caps=[CAP_REPLAY_IDEM, CAP_OVERFLOW_REFUND],
        severity="HIGH",
        cvss=8.2,
        cwe="CWE-20",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Fee bypass at {step1_endpoint} — suppress platform fee "
            "using is_fee_exempt=true or fee=0 — {step1_desc}\n"
            "Step 2: Negative amount at {step2_endpoint} results in platform "
            "paying the sender — {step2_desc}\n"
            "Impact: Zero-cost or profit-generating transactions at scale."
        ),
        impact_template=(
            "Fee exemption combined with negative amounts lets an attacker "
            "generate profit from each transaction instead of paying fees. "
            "At scale this drains platform revenue directly."
        ),
        recommendation=(
            "1. Fee exemption flags must be set server-side based on "
            "account tier — never trust client-supplied exemption flags.\n"
            "2. Reject negative amounts before fee calculation.\n"
            "3. Audit all zero-fee or negative transactions."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_STREAMING_1",
        name="Subscription Bypass + Download Token Replay → Free Premium",
        required_caps=[CAP_ACCESS_PREMIUM, CAP_REPLAY_DOWNLOAD],
        optional_caps=[CAP_BYPASS_DEVICE_CAP, CAP_ACCESS_RESOURCE],
        severity="CRITICAL",
        cvss=8.5,
        cwe="CWE-285",
        owasp="API5:2023 Broken Function Level Authorization",
        narrative_template=(
            "Step 1: Subscription scope bypass at {step1_endpoint} — "
            "free-tier token accesses premium content — {step1_desc}\n"
            "Step 2: Download token replay at {step2_endpoint} — signed URL "
            "shared and replayed without auth — {step2_desc}\n"
            "Impact: Premium audio/content accessible permanently without "
            "a paid subscription. Shareable to unlimited users."
        ),
        impact_template=(
            "Free-tier users access premium endpoints and obtain download URLs. "
            "These URLs are then shareable — anyone with the URL can download "
            "premium content without any subscription. Direct revenue loss "
            "and royalty under-reporting to rights holders."
        ),
        recommendation=(
            "1. Validate subscription scope on every API request server-side.\n"
            "2. Use short-lived signed URLs (max 60 seconds) bound to the "
            "requesting user's device or IP.\n"
            "3. Invalidate URLs after first use for premium content."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_STREAMING_2",
        name="Stream Count Inflation + Resource IDOR → Royalty Fraud",
        required_caps=[CAP_INFLATE_STREAMS, CAP_ACCESS_RESOURCE],
        optional_caps=[CAP_EXECUTE_TWICE, CAP_BYPASS_DEVICE_CAP],
        severity="HIGH",
        cvss=7.8,
        cwe="CWE-770",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Stream count manipulation at {step1_endpoint} — "
            "duplicate play events inflate count — {step1_desc}\n"
            "Step 2: Resource IDOR at {step2_endpoint} — access other "
            "artists' analytics to verify counts increased — {step2_desc}\n"
            "Impact: Artificially inflate royalty payments for selected tracks. "
            "Chart manipulation and fraudulent royalty extraction."
        ),
        impact_template=(
            "Duplicate play events inflate stream counts for any track. "
            "IDOR on artist analytics confirms the inflation. "
            "Used for royalty fraud (direct financial extraction) or chart "
            "manipulation (promotional fraud). Scales with automation."
        ),
        recommendation=(
            "1. Deduplicate play events by (user_id, track_id, session_id).\n"
            "2. Require minimum 30 seconds of listening before counting a stream.\n"
            "3. Enforce ownership on artist analytics endpoints.\n"
            "4. Implement ML-based stream fraud detection."
        ),
    ),

    ChainRule(
        chain_id="CHAIN_STREAMING_3",
        name="Device Limit Bypass + Subscription Scope → Unlimited Account Sharing",
        required_caps=[CAP_BYPASS_DEVICE_CAP, CAP_ACCESS_PREMIUM],
        optional_caps=[CAP_REPLAY_DOWNLOAD, CAP_ACCESS_RESOURCE],
        severity="HIGH",
        cvss=7.5,
        cwe="CWE-770",
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        narrative_template=(
            "Step 1: Device limit bypass at {step1_endpoint} — register "
            "unlimited devices per account — {step1_desc}\n"
            "Step 2: Premium scope accessible on all registered devices "
            "at {step2_endpoint} — {step2_desc}\n"
            "Impact: One premium account shared across unlimited devices "
            "and users simultaneously."
        ),
        impact_template=(
            "Device limit bypass combined with premium scope access allows "
            "one premium subscription to serve unlimited concurrent users. "
            "Subscription revenue directly lost for each shared account."
        ),
        recommendation=(
            "1. Enforce device limits server-side by counting registered "
            "devices per account.\n"
            "2. Validate concurrent stream count per account in real time.\n"
            "3. Require re-authentication when device limit is exceeded."
        ),
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Extended capability classifier
# ─────────────────────────────────────────────────────────────────────────────

# FIX (BUG-12): guard flag prevents double-patching if extend_capability_classifier()
# is ever called more than once (e.g. from a concurrent register() call before
# the lock fix took effect, or during testing).
_classifier_extended = False


def extend_capability_classifier() -> None:
    """
    Patch CapabilityClassifier.classify() to recognise the new
    domain-specific categories from platform_attack_modules.py.
    Called once from DomainChainEngine.register().

    FIX (BUG-12): idempotent — safe to call multiple times without
    double-patching.
    """
    global _classifier_extended
    if _classifier_extended:
        return

    _orig_classify = CapabilityClassifier.classify

    def _extended_classify(self, finding: dict) -> set[str]:
        caps     = _orig_classify(self, finding)
        category = (finding.get("category") or "").lower()
        title    = (finding.get("title")    or "").lower()

        if "amount sign flip" in category or "negative amount" in title:
            caps.add(CAP_NEGATIVE_AMOUNT)
            caps.add(CAP_NEGATIVE_VALUE)

        if "currency confusion" in category or "currency" in title:
            caps.add(CAP_CURRENCY_CONFUSE)

        if "idempotency" in category or "idempotency" in title:
            caps.add(CAP_REPLAY_IDEM)
            caps.add(CAP_EXECUTE_TWICE)

        if "refund overflow" in category or "refund overflow" in title:
            caps.add(CAP_OVERFLOW_REFUND)

        if "webhook forgery" in category or "webhook" in title:
            caps.add(CAP_FORGE_WEBHOOK)
            caps.add(CAP_BYPASS_WORKFLOW)

        if "fee bypass" in category or "fee bypass" in title:
            caps.add(CAP_BYPASS_FEE)

        if "kyc bypass" in category or "sca bypass" in category:
            caps.add(CAP_BYPASS_KYC)
            caps.add(CAP_BYPASS_WORKFLOW)

        if "transfer idor" in category or "transfer idor" in title:
            caps.add(CAP_ACCESS_TRANSFER)
            caps.add(CAP_ACCESS_FOREIGN)

        if "subscription scope" in category or "premium" in title:
            caps.add(CAP_ACCESS_PREMIUM)

        if "stream count" in category or "play event" in title:
            caps.add(CAP_INFLATE_STREAMS)
            caps.add(CAP_EXECUTE_TWICE)

        if "download token" in category or "download url" in title:
            caps.add(CAP_REPLAY_DOWNLOAD)

        if "device limit" in category or "device" in title:
            caps.add(CAP_BYPASS_DEVICE_CAP)

        if "resource idor" in category and "streaming" in category:
            caps.add(CAP_ACCESS_RESOURCE)
            caps.add(CAP_ACCESS_FOREIGN)

        return caps

    CapabilityClassifier.classify = _extended_classify
    _classifier_extended = True


# ─────────────────────────────────────────────────────────────────────────────
# Domain chain engine
# ─────────────────────────────────────────────────────────────────────────────

class DomainChainEngine:
    """
    Extends the existing ChainEngine with domain-specific chain rules.
    Call register() once at startup to add rules to CHAIN_RULES.
    After that, ChainEngine.analyze() picks them up automatically.

    FIX (BUG-11): register() is now thread-safe via a class-level lock,
    preventing duplicate rule registration if two threads call register()
    concurrently before _registered is set.
    """

    _registered = False
    # FIX (BUG-11): lock prevents two concurrent callers both reading
    # _registered=False and registering rules twice.
    _lock = threading.Lock()

    @classmethod
    def register(cls) -> None:
        with cls._lock:
            if cls._registered:
                return
            existing_ids = {r.chain_id for r in CHAIN_RULES}
            for rule in _DOMAIN_CHAIN_RULES:
                if rule.chain_id not in existing_ids:
                    CHAIN_RULES.append(rule)
            extend_capability_classifier()
            cls._registered = True
            print(
                f"  [domain_chains] registered {len(_DOMAIN_CHAIN_RULES)} "
                f"fintech/streaming chain rules"
            )
