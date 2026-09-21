"""
BLFinder v3.1 — core/evidence/impact_assessor.py
PII / Credential Detection + Impact Scoring

Scans the attack response body for sensitive data and generates:
  1. A list of sensitive items found (with real field names and sample values)
  2. An impact score (0–100) for severity calibration
  3. A CVSS adjustment recommendation
  4. A human-readable impact statement for HackerOne reports

This answers the reviewer's question: "What data was actually exposed?"
Instead of: "Sensitive data may be exposed"
We say: "47 user email addresses, 3 password hashes, and 1 API key were exposed"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SensitivityLevel(str, Enum):
    CRITICAL = "CRITICAL"   
    HIGH     = "HIGH"       
    MEDIUM   = "MEDIUM"     
    LOW      = "LOW"        


@dataclass
class SensitiveItem:
    """A single sensitive data item found in the attack response."""
    field_name: str
    sensitivity: SensitivityLevel
    category: str               
    sample_value: str           
    full_path: str = ""         
    count: int = 1              
    description: str = ""      


@dataclass
class ImpactReport:
    """
    Complete impact assessment of an attack response.
    Attached to EvidencePackage.impact_report.
    """

    sensitive_items: list[SensitiveItem] = field(default_factory=list)


    impact_score: int = 0               
    cvss_adjustment: float = 0.0        


    has_credentials: bool = False       
    has_pii: bool = False               
    has_financial: bool = False         
    has_internal: bool = False          
    has_other_user_data: bool = False   


    total_records_exposed: int = 0      
    unique_users_exposed: int = 0       


    impact_statement: str = ""          
    h1_impact_section: str = ""         

    def __post_init__(self):
        self._compute_scores()

    def _compute_scores(self):
        if not self.sensitive_items:
            return

        score = 0
        for item in self.sensitive_items:
            if item.sensitivity == SensitivityLevel.CRITICAL:
                score += 30
            elif item.sensitivity == SensitivityLevel.HIGH:
                score += 20
            elif item.sensitivity == SensitivityLevel.MEDIUM:
                score += 10
            else:
                score += 5
            score += min(item.count, 10) * 2   

        self.impact_score = min(100, score)


        if self.has_credentials:
            self.cvss_adjustment = 2.5
        elif self.has_pii:
            self.cvss_adjustment = 1.5
        elif self.has_financial:
            self.cvss_adjustment = 2.0
        elif self.has_internal:
            self.cvss_adjustment = 1.0


class ImpactAssessor:
    """
    Scans API response bodies for sensitive data.

    Usage:
        report = ImpactAssessor.assess(
            attack_body=resp_body,
            baseline_body=base_body,
            endpoint="https://api.target.com/api/v1/users/me",
        )
        print(report.impact_statement)
        print(report.h1_impact_section)
    """




    FIELD_PATTERNS: list[tuple[re.Pattern, SensitivityLevel, str, str]] = [



        (re.compile(r'\bpassword(_hash|_digest|_encrypted)?\b', re.I),
         SensitivityLevel.CRITICAL, "credential", "Password or password hash exposed"),
        (re.compile(r'\b(api_key|apikey|api_secret)\b', re.I),
         SensitivityLevel.CRITICAL, "credential", "API key/secret exposed"),
        (re.compile(r'\b(access_token|auth_token|bearer_token|jwt)\b', re.I),
         SensitivityLevel.CRITICAL, "credential", "Authentication token exposed"),
        (re.compile(r'\b(private_key|secret_key|signing_key)\b', re.I),
         SensitivityLevel.CRITICAL, "credential", "Cryptographic key exposed"),
        (re.compile(r'\b(client_secret|oauth_secret)\b', re.I),
         SensitivityLevel.CRITICAL, "credential", "OAuth client secret exposed"),
        (re.compile(r'\b(db_password|database_password|db_pass)\b', re.I),
         SensitivityLevel.CRITICAL, "credential", "Database password exposed"),


        (re.compile(r'\b(card_number|credit_card|pan|primary_account_number)\b', re.I),
         SensitivityLevel.CRITICAL, "financial", "Credit card number exposed"),
        (re.compile(r'\bcvv\b|\bcvc\b|\bcvc2\b', re.I),
         SensitivityLevel.CRITICAL, "financial", "Card security code exposed"),
        (re.compile(r'\b(bank_account|account_number|iban|routing_number)\b', re.I),
         SensitivityLevel.CRITICAL, "financial", "Bank account information exposed"),


        (re.compile(r'\b(ssn|social_security|national_id|tax_id)\b', re.I),
         SensitivityLevel.CRITICAL, "pii", "Government ID number exposed"),
        (re.compile(r'\b(email|email_address)\b', re.I),
         SensitivityLevel.HIGH, "pii", "Email address exposed"),
        (re.compile(r'\b(phone|mobile|phone_number|mobile_number)\b', re.I),
         SensitivityLevel.HIGH, "pii", "Phone number exposed"),
        (re.compile(r'\b(dob|date_of_birth|birthdate|birthday)\b', re.I),
         SensitivityLevel.HIGH, "pii", "Date of birth exposed"),
        (re.compile(r'\b(full_name|first_name|last_name|surname)\b', re.I),
         SensitivityLevel.HIGH, "pii", "Personal name exposed"),
        (re.compile(r'\b(address|street|city|postal_code|zip_code)\b', re.I),
         SensitivityLevel.HIGH, "pii", "Physical address exposed"),
        (re.compile(r'\b(passport|passport_number)\b', re.I),
         SensitivityLevel.CRITICAL, "pii", "Passport number exposed"),


        (re.compile(r'\b(balance|account_balance|wallet_balance)\b', re.I),
         SensitivityLevel.HIGH, "financial", "Financial balance exposed"),
        (re.compile(r'\b(salary|income|revenue|earnings)\b', re.I),
         SensitivityLevel.HIGH, "financial", "Financial earnings data exposed"),
        (re.compile(r'\b(transaction_id|payment_id|invoice_id)\b', re.I),
         SensitivityLevel.MEDIUM, "financial", "Payment record IDs exposed"),


        (re.compile(r'\b(role|roles|permissions|scopes)\b', re.I),
         SensitivityLevel.HIGH, "privilege", "Role/permission data exposed"),
        (re.compile(r'\b(is_admin|is_staff|is_superuser)\b', re.I),
         SensitivityLevel.HIGH, "privilege", "Admin flag exposed"),


        (re.compile(r'\b(db_host|database_url|connection_string)\b', re.I),
         SensitivityLevel.CRITICAL, "internal", "Database connection string exposed"),
        (re.compile(r'\b(internal_note|admin_note|staff_note)\b', re.I),
         SensitivityLevel.MEDIUM, "internal", "Internal notes exposed"),
        (re.compile(r'\b(secret|internal_secret|app_secret)\b', re.I),
         SensitivityLevel.HIGH, "internal", "Application secret exposed"),
        (re.compile(r'\b(ip_address|server_ip)\b', re.I),
         SensitivityLevel.MEDIUM, "internal", "Internal IP address exposed"),


        (re.compile(r'\b(latitude|longitude|lat|lng|coordinates|location)\b', re.I),
         SensitivityLevel.MEDIUM, "location", "Location data exposed"),
    ]


    VALUE_PATTERNS: list[tuple[re.Pattern, str, str]] = [

        (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
         "pii", "Email address"),
        (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),
         "financial", "Visa card number"),
        (re.compile(r'\b5[1-5][0-9]{14}\b'),
         "financial", "Mastercard number"),
        (re.compile(r'\b3[47][0-9]{13}\b'),
         "financial", "Amex card number"),
        (re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{20,}\b'),
         "credential", "Stripe API key"),
        (re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
         "credential", "GitHub personal access token"),
        (re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
         "credential", "AWS access key"),
        (re.compile(r'\b[A-Fa-f0-9]{32}\b'),
         "credential", "Possible MD5 hash"),
        (re.compile(r'\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}'),
         "credential", "bcrypt password hash"),
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
         "pii", "US SSN pattern"),
        (re.compile(r'\+?[0-9]{10,14}\b'),
         "pii", "Phone number"),
    ]

    @classmethod
    def assess(
        cls,
        attack_body: str,
        baseline_body: str = "",
        endpoint: str = "",
    ) -> ImpactReport:
        """
        Main entry point. Assess the impact of a vulnerability by scanning
        the attack response for sensitive data.

        Args:
            attack_body:   The response body from the exploit request
            baseline_body: The normal response body (for comparison)
            endpoint:      The endpoint URL (for context)

        Returns:
            ImpactReport with all sensitive items and impact assessment
        """
        report = ImpactReport()


        attack_data = cls._safe_parse(attack_body)

        if attack_data is None:

            cls._scan_raw_body(report, attack_body)
        else:

            cls._scan_json(report, attack_data, prefix="")
            cls._scan_raw_body(report, attack_body)  


        report.sensitive_items = cls._dedupe(report.sensitive_items)


        for item in report.sensitive_items:
            if item.category == "credential":
                report.has_credentials = True
            elif item.category == "pii":
                report.has_pii = True
            elif item.category == "financial":
                report.has_financial = True
            elif item.category in ("internal", "privilege"):
                report.has_internal = True


        if isinstance(attack_data, list):
            report.total_records_exposed = len(attack_data)
        elif isinstance(attack_data, dict):
            for key in ("users", "accounts", "records", "items", "data", "results"):
                if key in attack_data and isinstance(attack_data[key], list):
                    report.total_records_exposed = len(attack_data[key])
                    break


        report.impact_statement = cls._build_statement(report, endpoint)
        report.h1_impact_section = cls._build_h1_section(report, endpoint)

        return report

    @classmethod
    def _scan_json(cls, report: ImpactReport, data: Any, prefix: str, depth: int = 0):
        """Recursively scan a JSON object for sensitive field names."""
        if depth > 8:
            return

        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key

                for pattern, sensitivity, category, description in cls.FIELD_PATTERNS:
                    if pattern.search(key):
                        sample = cls._redact_value(value, category)
                        item = SensitiveItem(
                            field_name=key,
                            sensitivity=sensitivity,
                            category=category,
                            sample_value=sample,
                            full_path=path,
                            count=1,
                            description=description,
                        )
                        report.sensitive_items.append(item)
                        break


                if isinstance(value, (dict, list)) and depth < 8:
                    cls._scan_json(report, value, path, depth + 1)

        elif isinstance(data, list):
            if data:

                cls._scan_json(report, data[0], f"{prefix}[0]", depth + 1)

                for item in report.sensitive_items:
                    if item.full_path.startswith(f"{prefix}[0]"):
                        item.count = len(data)

    @classmethod
    def _scan_raw_body(cls, report: ImpactReport, body: str):
        """Scan raw response body text for sensitive value patterns."""
        for pattern, category, description in cls.VALUE_PATTERNS:
            matches = pattern.findall(body)
            if matches:

                already_found = any(
                    item.category == category and item.description == description
                    for item in report.sensitive_items
                )
                if not already_found:
                    sample = cls._redact_value(matches[0], category)
                    item = SensitiveItem(
                        field_name=f"[{description}]",
                        sensitivity=SensitivityLevel.HIGH,
                        category=category,
                        sample_value=sample,
                        full_path="",
                        count=len(matches),
                        description=f"{description} found in response ({len(matches)} occurrence{'s' if len(matches) > 1 else ''})",
                    )
                    report.sensitive_items.append(item)

    @classmethod
    def _redact_value(cls, value: Any, category: str) -> str:
        """Return a safely redacted sample value for reports."""
        if value is None:
            return "null"
        s = str(value)
        if not s:
            return '""'

        if category == "credential":
            if len(s) > 8:
                return f"{s[:4]}...{s[-2:]} [{len(s)} chars]"
            return "****"

        if category == "financial":
            if len(s) >= 4:
                return f"****{s[-4:]}"
            return "****"

        if category == "pii":
            if "@" in s:  
                parts = s.split("@")
                return f"{parts[0][:2]}***@{parts[1]}"
            if len(s) > 4:
                return f"{s[:2]}***{s[-2:]}"
            return "***"


        if isinstance(value, dict):
            return f"{{...}} ({len(value)} keys)"
        if isinstance(value, list):
            return f"[...] ({len(value)} items)"
        if len(s) > 20:
            return f"{s[:10]}... [{len(s)} chars]"
        return s

    @classmethod
    def _build_statement(cls, report: ImpactReport, endpoint: str) -> str:
        """Build a human-readable impact statement."""
        if not report.sensitive_items:
            return "No sensitive data patterns detected in the attack response."

        parts = []

        if report.has_credentials:
            cred_items = [i for i in report.sensitive_items if i.category == "credential"]
            parts.append(
                f"Authentication credentials exposed "
                f"({', '.join(i.description for i in cred_items[:2])})"
            )

        if report.has_pii:
            pii_items = [i for i in report.sensitive_items if i.category == "pii"]
            total_pii = sum(i.count for i in pii_items)
            parts.append(
                f"Personal data exposed: "
                f"{', '.join(i.field_name for i in pii_items[:3])}"
                + (f" ({total_pii} records)" if report.total_records_exposed > 1 else "")
            )

        if report.has_financial:
            fin_items = [i for i in report.sensitive_items if i.category == "financial"]
            parts.append(
                f"Financial data exposed: {', '.join(i.description for i in fin_items[:2])}"
            )

        if report.has_internal:
            int_items = [i for i in report.sensitive_items if i.category in ("internal", "privilege")]
            parts.append(
                f"Internal/privileged data exposed: "
                f"{', '.join(i.field_name for i in int_items[:3])}"
            )

        if report.total_records_exposed > 1:
            parts.append(f"{report.total_records_exposed} records affected")

        statement = ". ".join(parts) + "." if parts else "Sensitive data exposed."
        if endpoint:
            statement = f"Vulnerability at {endpoint}: {statement}"

        return statement

    @classmethod
    def _build_h1_section(cls, report: ImpactReport, endpoint: str) -> str:
        """Build the HackerOne-ready Impact section."""
        if not report.sensitive_items:
            return "The impact of this vulnerability is under assessment."

        lines = []

        if report.has_credentials:
            lines.append("**Authentication Impact:**")
            for item in [i for i in report.sensitive_items if i.category == "credential"]:
                lines.append(f"- {item.description}: `{item.sample_value}`")
            lines.append("")

        if report.has_pii:
            pii_items = [i for i in report.sensitive_items if i.category == "pii"]
            total = sum(i.count for i in pii_items)
            lines.append(f"**Privacy Impact** ({total} records affected):")
            for item in pii_items[:5]:
                count_str = f" × {item.count}" if item.count > 1 else ""
                lines.append(f"- {item.description}{count_str}: `{item.sample_value}`")
            lines.append("")

        if report.has_financial:
            lines.append("**Financial Data Impact:**")
            for item in [i for i in report.sensitive_items if i.category == "financial"]:
                lines.append(f"- {item.description}: `{item.sample_value}`")
            lines.append("")

        if report.has_internal:
            lines.append("**Internal Data Exposure:**")
            for item in [i for i in report.sensitive_items if i.category in ("internal", "privilege")]:
                lines.append(f"- {item.description}: `{item.sample_value}`")
            lines.append("")

        if report.total_records_exposed > 1:
            lines.append(
                f"**Scale:** {report.total_records_exposed} records were accessible "
                f"through this vulnerability at `{endpoint}`."
            )

        return "\n".join(lines)

    @staticmethod
    def _safe_parse(body: str) -> Any:
        try:
            return json.loads(body.strip())
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _dedupe(items: list[SensitiveItem]) -> list[SensitiveItem]:
        seen = set()
        unique = []
        for item in items:
            key = (item.field_name, item.category)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique
