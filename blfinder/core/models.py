"""
BLFinder v2.1 — Shared data models
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ProofOfConcept:
    """Structured PoC with multiple reproduction formats."""
    summary: str                     # One-line summary of what was proven
    curl_command: str                # Ready-to-run curl command
    python_script: str               # Standalone Python script
    burp_request: str                # Raw HTTP request for Burp Repeater
    expected_result: str             # What the tester should observe
    steps: list[str] = field(default_factory=list)   # Manual reproduction steps
    video_note: str = ""             # Notes for screen recording


@dataclass
class Finding:
    title: str
    severity: Severity
    category: str
    description: str
    request: dict
    response_summary: str
    evidence: str
    recommendation: str
    poc: Optional[ProofOfConcept] = None
    cwe: str = ""
    cvss: float = 0.0
    owasp: str = ""
    confirmed: bool = False          # Re-verified, not just heuristic
    confidence: int = 0              # 0–100
    confidence_reasons: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    endpoint: str = ""
    parameter: str = ""


@dataclass
class ScanConfig:
    target_url: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    auth_token: str = ""
    second_user_token: str = ""
    third_user_token: str = ""
    api_key_sid: str = ""
    api_key_secret: str = ""
    second_api_key_sid: str = ""
    second_api_key_secret: str = ""
    third_api_key_sid: str = ""
    third_api_key_secret: str = ""
    no_auth_check: bool = True
    timeout: int = 20
    rate_limit: float = 0.3
    max_redirects: int = 5
    verify_ssl: bool = False
    proxy: str = ""
    wordlist_params: list = field(default_factory=list)
    custom_payloads: dict = field(default_factory=dict)
    user_agent_rotate: bool = True
    smart_discovery: bool = True
    fuzz_depth: int = 2
    respect_robots: bool = False
    verbose: bool = False
    output_dir: str = "."
    # Resume / checkpointing
    checkpoint_path: str = ""        # Set by CLI; empty disables checkpointing
    resume: bool = False             # If True, skip endpoints already in the checkpoint
    # FP reduction settings
    confirmation_attempts: int = 2   # Re-verify N times before reporting
    similarity_threshold: float = 0.15  # Min response diff to flag IDOR
    min_confidence: int = 40         # Skip findings below this confidence
