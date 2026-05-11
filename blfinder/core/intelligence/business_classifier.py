"""
BLFinder Phase 4 — core/intelligence/business_classifier.py
Business Context Classifier + Attack Planner

Classifies every endpoint by its business function BEFORE running attack modules.
Runs only the most relevant modules per endpoint type — 3x faster, less noise.

6 endpoint profiles:
  payment           → price, race, quantity (highest bounty)
  authentication    → JWT, enumeration, workflow bypass
  admin             → BFLA, privilege escalation, mass assignment
  user_data         → IDOR, BOPLA, mass assignment
  financial_transfer → race, negative, IDOR
  reward_loyalty    → coupon, race, workflow bypass
  default           → all modules

Attack plan is generated pre-scan and printed if --classify flag is set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ── Endpoint profiles ─────────────────────────────────────────────────────────

ENDPOINT_PROFILES: dict[str, dict] = {
    "payment": {
        "url_patterns": [
            "pay", "checkout", "purchase", "billing", "invoice",
            "cart", "order", "subscription", "charge", "receipt",
        ],
        "body_signals": [
            "price", "amount", "total", "card", "payment_method",
            "coupon", "discount", "currency", "cost", "fee",
        ],
        "priority_modules": [
            "price_manipulation", "negative_quantity",
            "coupon_stacking", "race_condition",
            "state_machine_abuse", "integer_overflow",
        ],
        "skip_modules": [
            "account_enumeration", "graphql", "soft_delete_bypass",
            "parameter_pollution",
        ],
        "estimated_bounty": "$1,000–$10,000",
        "bounty_score": 90,
    },
    "authentication": {
        "url_patterns": [
            "login", "signin", "sign-in", "token", "auth",
            "oauth", "session", "logout", "password", "credential",
            "register", "signup", "forgot", "reset", "verify",
        ],
        "body_signals": [
            "email", "password", "username", "credential",
            "refresh_token", "access_token", "code", "grant_type",
        ],
        "priority_modules": [
            "jwt_manipulation", "account_enumeration",
            "workflow_bypass", "blind_idor",
        ],
        "skip_modules": [
            "price_manipulation", "coupon_stacking",
            "integer_overflow", "soft_delete_bypass",
        ],
        "estimated_bounty": "$500–$5,000",
        "bounty_score": 75,
    },
    "admin": {
        "url_patterns": [
            "admin", "manage", "management", "internal",
            "dashboard", "staff", "backoffice", "superuser",
            "console", "operator", "moderator",
        ],
        "body_signals": [
            "role", "admin", "permission", "is_admin", "staff",
            "privilege", "access_level", "scope",
        ],
        "priority_modules": [
            "privilege_escalation", "bfla",
            "mass_assignment", "idor_bola", "bopla",
        ],
        "skip_modules": [
            "coupon_stacking", "time_bypass",
            "parameter_pollution", "integer_overflow",
        ],
        "estimated_bounty": "$2,000–$15,000",
        "bounty_score": 95,
    },
    "user_data": {
        "url_patterns": [
            "profile", "account", "user", "me", "settings",
            "preferences", "personal", "identity", "kyc",
        ],
        "body_signals": [
            "user_id", "account_id", "profile_id",
            "name", "email", "phone", "address", "dob",
        ],
        "priority_modules": [
            "idor_bola", "bopla", "mass_assignment",
            "hidden_parameter", "blind_idor",
        ],
        "skip_modules": [
            "race_condition", "integer_overflow",
            "coupon_stacking", "time_bypass",
        ],
        "estimated_bounty": "$300–$3,000",
        "bounty_score": 60,
    },
    "financial_transfer": {
        "url_patterns": [
            "transfer", "withdraw", "withdrawal", "send",
            "remit", "remittance", "payout", "disbursement",
            "credit", "debit", "fund",
        ],
        "body_signals": [
            "amount", "to_account", "from_account",
            "recipient", "destination", "source", "balance",
        ],
        "priority_modules": [
            "race_condition", "negative_quantity",
            "idor_bola", "price_manipulation",
            "integer_overflow", "workflow_bypass",
        ],
        "skip_modules": [
            "graphql", "coupon_stacking",
            "soft_delete_bypass", "parameter_pollution",
        ],
        "estimated_bounty": "$2,000–$20,000",
        "bounty_score": 98,
    },
    "reward_loyalty": {
        "url_patterns": [
            "redeem", "reward", "coupon", "referral",
            "voucher", "promo", "discount", "points",
            "loyalty", "bonus", "gift", "cashback",
        ],
        "body_signals": [
            "coupon_code", "promo_code", "referral_code",
            "points", "reward_id", "voucher_id",
        ],
        "priority_modules": [
            "coupon_stacking", "race_condition",
            "workflow_bypass", "state_machine_abuse",
        ],
        "skip_modules": [
            "graphql", "integer_overflow",
            "soft_delete_bypass",
        ],
        "estimated_bounty": "$200–$3,000",
        "bounty_score": 55,
    },
}

# Default profile — run everything
DEFAULT_PROFILE: dict = {
    "url_patterns": [],
    "body_signals": [],
    "priority_modules": [],
    "skip_modules": [],
    "estimated_bounty": "$100–$5,000",
    "bounty_score": 50,
}


@dataclass
class EndpointProfile:
    """Classification result for a single endpoint."""
    endpoint:         str
    profile_name:     str
    confidence:       float         # 0.0–1.0
    priority_modules: list[str] = field(default_factory=list)
    skip_modules:     list[str] = field(default_factory=list)
    estimated_bounty: str = ""
    bounty_score:     int = 0
    signals:          list[str] = field(default_factory=list)

    @property
    def is_high_value(self) -> bool:
        return self.bounty_score >= 75


@dataclass
class AttackPlan:
    """Pre-scan attack plan for all endpoints."""
    total_endpoints:     int = 0
    classified:          list[EndpointProfile] = field(default_factory=list)
    unclassified:        list[str] = field(default_factory=list)
    estimated_scan_time: float = 0.0
    high_value_count:    int = 0
    attack_queue:        list[tuple] = field(default_factory=list)  # (url, [modules])

    def print_report(self, verbose: bool = False):
        """Print a pre-scan attack plan to terminal."""
        print(f"\n[*] Attack Plan — {self.total_endpoints} endpoints")
        print(f"    High-value targets : {self.high_value_count}")
        print(f"    Unclassified       : {len(self.unclassified)}")
        print()

        # Group by profile
        by_profile: dict[str, list[EndpointProfile]] = {}
        for ep in self.classified:
            by_profile.setdefault(ep.profile_name, []).append(ep)

        for profile_name, eps in sorted(
            by_profile.items(),
            key=lambda x: -max(e.bounty_score for e in x[1]),
        ):
            profile = ENDPOINT_PROFILES.get(profile_name, DEFAULT_PROFILE)
            print(
                f"  [{profile_name.upper():<20}] "
                f"{len(eps):>3} endpoint(s) | "
                f"Bounty: {profile.get('estimated_bounty', '?')}"
            )
            if verbose:
                for ep in eps[:3]:
                    print(f"    → {ep.endpoint[:60]}")

        print()


class BusinessClassifier:
    """
    Classifies endpoints by business function and generates an attack plan.

    Usage:
        classifier = BusinessClassifier()
        plan = classifier.build_plan(endpoints)
        plan.print_report()

        for url, modules in plan.attack_queue:
            # Run only the modules for this endpoint type
    """

    def classify(
        self,
        endpoint: str,
        body:     dict | None = None,
        params:   dict | None = None,
    ) -> EndpointProfile:
        """
        Classify a single endpoint by its URL, body, and params.
        Returns an EndpointProfile with priority/skip module lists.
        """
        url_lower   = endpoint.lower()
        body_keys   = list((body or {}).keys())
        param_keys  = list((params or {}).keys())
        all_signals = body_keys + param_keys

        best_profile = None
        best_score   = 0.0
        best_signals: list[str] = []

        for profile_name, profile in ENDPOINT_PROFILES.items():
            score   = 0.0
            signals = []

            # URL pattern matching
            for pattern in profile["url_patterns"]:
                if pattern in url_lower:
                    score += 1.0
                    signals.append(f"URL contains '{pattern}'")

            # Body/param signal matching
            for signal in profile["body_signals"]:
                if any(signal in key.lower() for key in all_signals):
                    score += 0.75
                    signals.append(f"Body/param has '{signal}'")

            # Normalize by number of patterns
            total_patterns = len(profile["url_patterns"]) + len(profile["body_signals"])
            if total_patterns > 0:
                score = score / total_patterns

            if score > best_score:
                best_score   = score
                best_profile = profile_name
                best_signals = signals

        # Minimum confidence threshold
        if best_score < 0.05 or best_profile is None:
            return EndpointProfile(
                endpoint=endpoint,
                profile_name="default",
                confidence=0.0,
                priority_modules=[],
                skip_modules=[],
                estimated_bounty=DEFAULT_PROFILE["estimated_bounty"],
                bounty_score=DEFAULT_PROFILE["bounty_score"],
                signals=["No clear business profile detected"],
            )

        profile = ENDPOINT_PROFILES[best_profile]
        return EndpointProfile(
            endpoint=endpoint,
            profile_name=best_profile,
            confidence=min(1.0, best_score * 3),   # Scale for readability
            priority_modules=profile["priority_modules"],
            skip_modules=profile["skip_modules"],
            estimated_bounty=profile["estimated_bounty"],
            bounty_score=profile["bounty_score"],
            signals=best_signals[:5],
        )

    def build_plan(self, endpoints: list[dict]) -> AttackPlan:
        """
        Build a complete attack plan for a list of endpoints.
        Sorts by estimated bounty value — highest first.
        """
        plan = AttackPlan(total_endpoints=len(endpoints))

        for ep in endpoints:
            url    = ep.get("url", "")
            body   = ep.get("body", {})
            params = ep.get("params", {})

            profile = self.classify(url, body, params)

            if profile.profile_name == "default" and profile.confidence == 0.0:
                plan.unclassified.append(url)
            else:
                plan.classified.append(profile)
                if profile.is_high_value:
                    plan.high_value_count += 1

        # Sort by bounty score descending
        plan.classified.sort(key=lambda x: x.bounty_score, reverse=True)

        # Build ordered attack queue
        for profile in plan.classified:
            plan.attack_queue.append((
                profile.endpoint,
                profile.priority_modules,
            ))
        for url in plan.unclassified:
            plan.attack_queue.append((url, []))  # Run all modules

        return plan

    def get_modules_for_endpoint(
        self,
        endpoint: str,
        body:     dict | None = None,
        all_modules: list[str] | None = None,
    ) -> list[str]:
        """
        Return an ordered list of modules to run for this endpoint.
        Priority modules first, skip modules excluded.
        """
        profile    = self.classify(endpoint, body)
        all_mods   = list(all_modules or _ALL_MODULES)
        priority   = profile.priority_modules
        skip       = set(profile.skip_modules)

        ordered = (
            [m for m in priority if m in all_mods and m not in skip]
            + [m for m in all_mods if m not in priority and m not in skip]
        )
        return ordered


# ── All module names for reference ────────────────────────────────────────────

_ALL_MODULES = [
    "price_manipulation", "negative_quantity", "workflow_bypass",
    "mass_assignment", "idor_bola", "bopla", "privilege_escalation",
    "bfla", "coupon_stacking", "time_bypass", "integer_overflow",
    "hidden_parameter", "state_machine_abuse", "race_condition",
    "jwt_manipulation", "account_enumeration", "limit_offset",
    "soft_delete_bypass", "http_method_override", "parameter_pollution",
    "blind_idor", "graphql",
]
