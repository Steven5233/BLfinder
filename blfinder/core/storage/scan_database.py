"""
BLFinder Phase 5 — core/storage/scan_database.py
Persistent SQLite Finding Store

Solves three real problems:
  1. Don't re-report the same bug twice
  2. Track what programs have been tested
  3. Export directly to HackerOne via API

Schema:
  findings:  All discovered findings with dedup hash
  scans:     Scan history (target, date, finding count)
  programs:  HackerOne/Bugcrowd program handles + scope

Usage:
    db = ScanDatabase("~/.blfinder.db")
    await db.init()

    await db.save_scan(target="api.target.com", program="target_h1")
    new, dupes = await db.save_findings(findings, scan_id, program="target_h1")

    # Export to HackerOne
    await db.export_to_hackerone(finding_id, h1_token, program="target_h1")

    # Search history
    results = await db.search("IDOR payment")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

try:
    import aiosqlite
    _HAS_AIOSQLITE = True
except ImportError:
    _HAS_AIOSQLITE = False

try:
    import aiohttp as _aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False



_H1_API_BASE     = "https://api.hackerone.com/v1"
_H1_REPORTS_URL  = f"{_H1_API_BASE}/reports"


@dataclass
class DBFinding:
    """A finding as stored in the database."""
    id:            int | None = None
    title:         str = ""
    severity:      str = ""
    category:      str = ""
    endpoint:      str = ""
    parameter:     str = ""
    evidence:      str = ""
    description:   str = ""
    recommendation: str = ""
    cwe:           str = ""
    cvss:          float = 0.0
    owasp:         str = ""
    confirmed:     bool = False
    confidence:    int = 0
    dedup_hash:    str = ""
    program:       str = ""
    scan_id:       int | None = None
    reported_at:   str | None = None
    h1_report_id:  str | None = None
    bounty_amount: float = 0.0
    status:        str = "new"     
    created_at:    str = ""
    verified_curl: str = ""


@dataclass
class DBScan:
    """A scan session as stored in the database."""
    id:            int | None = None
    target:        str = ""
    program:       str = ""
    started_at:    str = ""
    completed_at:  str | None = None
    finding_count: int = 0
    config_json:   str = ""


@dataclass
class DBStats:
    """Aggregated statistics from the database."""
    total_findings:     int = 0
    total_confirmed:    int = 0
    total_reported:     int = 0
    total_bounty:       float = 0.0
    by_severity:        dict[str, int] = None
    by_program:         dict[str, int] = None
    by_category:        dict[str, int] = None
    top_endpoints:      list[str] = None
    recent_findings:    list[DBFinding] = None


class ScanDatabase:
    """
    Async SQLite database for BLFinder finding persistence.

    All methods are async and safe to call from within the scanner's event loop.
    Requires: pip install aiosqlite --break-system-packages
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        target       TEXT NOT NULL,
        program      TEXT DEFAULT '',
        started_at   TEXT NOT NULL,
        completed_at TEXT,
        finding_count INTEGER DEFAULT 0,
        config_json  TEXT DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS findings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        title         TEXT NOT NULL,
        severity      TEXT NOT NULL,
        category      TEXT DEFAULT '',
        endpoint      TEXT DEFAULT '',
        parameter     TEXT DEFAULT '',
        evidence      TEXT DEFAULT '',
        description   TEXT DEFAULT '',
        recommendation TEXT DEFAULT '',
        cwe           TEXT DEFAULT '',
        cvss          REAL DEFAULT 0.0,
        owasp         TEXT DEFAULT '',
        confirmed     INTEGER DEFAULT 0,
        confidence    INTEGER DEFAULT 0,
        dedup_hash    TEXT NOT NULL,
        program       TEXT DEFAULT '',
        scan_id       INTEGER REFERENCES scans(id),
        reported_at   TEXT,
        h1_report_id  TEXT,
        bounty_amount REAL DEFAULT 0.0,
        status        TEXT DEFAULT 'new',
        created_at    TEXT NOT NULL,
        verified_curl TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS programs (
        handle            TEXT PRIMARY KEY,
        display_name      TEXT DEFAULT '',
        scope_urls        TEXT DEFAULT '[]',
        out_of_scope_urls TEXT DEFAULT '[]',
        last_scanned      TEXT,
        total_findings    INTEGER DEFAULT 0,
        total_bounty      REAL DEFAULT 0.0
    );

    CREATE INDEX IF NOT EXISTS idx_findings_dedup    ON findings(dedup_hash);
    CREATE INDEX IF NOT EXISTS idx_findings_program  ON findings(program);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
    CREATE INDEX IF NOT EXISTS idx_scans_target      ON scans(target);
    """

    def __init__(self, db_path: str = "~/.blfinder.db"):
        self.db_path = os.path.expanduser(db_path)
        self._db: "aiosqlite.Connection | None" = None

    async def init(self):
        """Initialise the database — call once before any other method."""
        if not _HAS_AIOSQLITE:
            raise RuntimeError(
                "aiosqlite required: pip install aiosqlite --break-system-packages"
            )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(self._SCHEMA)
        await self._db.commit()

    async def close(self):
        if self._db:
            await self._db.close()
            self._db = None

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, *args):
        await self.close()



    async def start_scan(self, target: str, program: str = "", config: dict = None) -> int:
        """Start a new scan session. Returns scan_id."""
        now = _now()
        async with self._db.execute(
            """INSERT INTO scans (target, program, started_at, config_json)
               VALUES (?, ?, ?, ?)""",
            (target, program, now, json.dumps(config or {})),
        ) as cur:
            scan_id = cur.lastrowid
        await self._db.commit()
        return scan_id

    async def finish_scan(self, scan_id: int, finding_count: int):
        """Mark a scan as complete with its final finding count."""
        await self._db.execute(
            "UPDATE scans SET completed_at=?, finding_count=? WHERE id=?",
            (_now(), finding_count, scan_id),
        )
        await self._db.commit()



    async def save_findings(
        self,
        findings:   list,          
        scan_id:    int | None = None,
        program:    str = "",
    ) -> tuple[int, int]:
        """
        Save a list of findings, skipping duplicates.

        Returns:
            (new_count, duplicate_count)
        """
        new_count  = 0
        dupe_count = 0

        for f in findings:
            dedup_hash = _make_dedup_hash(f)
            exists     = await self._check_duplicate(dedup_hash, program)

            if exists:
                dupe_count += 1
                continue

            pkg = getattr(f, "evidence_package", None)
            verified_curl = pkg.verified_curl if pkg else ""

            await self._db.execute(
                """INSERT INTO findings (
                    title, severity, category, endpoint, parameter,
                    evidence, description, recommendation, cwe, cvss, owasp,
                    confirmed, confidence, dedup_hash, program, scan_id,
                    status, created_at, verified_curl
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f.title,
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    getattr(f, "category", ""),
                    getattr(f, "endpoint", ""),
                    getattr(f, "parameter", ""),
                    getattr(f, "evidence", ""),
                    getattr(f, "description", ""),
                    getattr(f, "recommendation", ""),
                    getattr(f, "cwe", ""),
                    float(getattr(f, "cvss", 0.0)),
                    getattr(f, "owasp", ""),
                    1 if getattr(f, "confirmed", False) else 0,
                    int(getattr(f, "confidence", 0)),
                    dedup_hash,
                    program,
                    scan_id,
                    "new",
                    _now(),
                    verified_curl,
                ),
            )
            new_count += 1

        await self._db.commit()


        if program:
            await self._update_program_stats(program)

        return new_count, dupe_count

    async def get_findings(
        self,
        program:      str = "",
        severity:     str = "",
        status:       str = "",
        confirmed_only: bool = False,
        limit:        int = 100,
        offset:       int = 0,
    ) -> list[DBFinding]:
        """Retrieve findings with optional filters."""
        conditions = []
        params: list = []

        if program:
            conditions.append("program = ?")
            params.append(program)
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if status:
            conditions.append("status = ?")
            params.append(status)
        if confirmed_only:
            conditions.append("confirmed = 1")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        async with self._db.execute(
            f"""SELECT * FROM findings
               {where}
               ORDER BY
                 CASE severity
                   WHEN 'CRITICAL' THEN 0
                   WHEN 'HIGH'     THEN 1
                   WHEN 'MEDIUM'   THEN 2
                   WHEN 'LOW'      THEN 3
                   ELSE 4 END,
                 created_at DESC
               LIMIT ? OFFSET ?""",
            params,
        ) as cur:
            rows = await cur.fetchall()

        return [_row_to_finding(row) for row in rows]

    async def search(self, query: str, limit: int = 50) -> list[DBFinding]:
        """Full-text search across titles and evidence."""
        pattern = f"%{query}%"
        async with self._db.execute(
            """SELECT * FROM findings
               WHERE title LIKE ?
                  OR evidence LIKE ?
                  OR description LIKE ?
                  OR endpoint LIKE ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (pattern, pattern, pattern, pattern, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(row) for row in rows]

    async def mark_reported(
        self,
        finding_id:   int,
        h1_report_id: str = "",
        bounty:       float = 0.0,
    ):
        """Mark a finding as reported with optional HackerOne report ID."""
        await self._db.execute(
            """UPDATE findings
               SET status='reported', reported_at=?, h1_report_id=?, bounty_amount=?
               WHERE id=?""",
            (_now(), h1_report_id, bounty, finding_id),
        )
        await self._db.commit()

    async def mark_status(self, finding_id: int, status: str):
        """Update finding status: new | reported | triaged | resolved | duplicate."""
        valid = {"new", "reported", "triaged", "resolved", "duplicate", "informative"}
        if status not in valid:
            raise ValueError(f"Invalid status: {status}. Must be one of {valid}")
        await self._db.execute(
            "UPDATE findings SET status=? WHERE id=?",
            (status, finding_id),
        )
        await self._db.commit()



    async def _check_duplicate(self, dedup_hash: str, program: str = "") -> bool:
        """Return True if this finding hash already exists for this program."""
        conditions = ["dedup_hash = ?"]
        params: list = [dedup_hash]
        if program:
            conditions.append("program = ?")
            params.append(program)
        async with self._db.execute(
            f"SELECT 1 FROM findings WHERE {' AND '.join(conditions)} LIMIT 1",
            params,
        ) as cur:
            return await cur.fetchone() is not None

    async def is_duplicate(self, finding, program: str = "") -> bool:
        """Public API: check if a Finding object is already in the DB."""
        return await self._check_duplicate(_make_dedup_hash(finding), program)



    async def register_program(
        self,
        handle:       str,
        display_name: str = "",
        scope_urls:   list[str] | None = None,
        out_of_scope: list[str] | None = None,
    ):
        """Register a bug bounty program."""
        await self._db.execute(
            """INSERT OR REPLACE INTO programs
               (handle, display_name, scope_urls, out_of_scope_urls, last_scanned)
               VALUES (?, ?, ?, ?, ?)""",
            (
                handle, display_name,
                json.dumps(scope_urls or []),
                json.dumps(out_of_scope or []),
                _now(),
            ),
        )
        await self._db.commit()

    async def _update_program_stats(self, handle: str):
        async with self._db.execute(
            "SELECT COUNT(*), SUM(bounty_amount) FROM findings WHERE program = ?",
            (handle,),
        ) as cur:
            row = await cur.fetchone()
        if row:
            count, total_bounty = row[0] or 0, row[1] or 0.0
            await self._db.execute(
                """INSERT OR REPLACE INTO programs
                   (handle, total_findings, total_bounty, last_scanned)
                   VALUES (
                       ?,
                       ?,
                       ?,
                       COALESCE(
                           (SELECT last_scanned FROM programs WHERE handle=?),
                           ?
                       )
                   )""",
                (handle, count, total_bounty, handle, _now()),
            )
            await self._db.commit()



    async def export_to_hackerone(
        self,
        finding_id:     int,
        h1_token:       str,
        program_handle: str,
    ) -> dict:
        """
        Export a finding to HackerOne as a draft report via the v1 API.

        Args:
            finding_id:     Database finding ID
            h1_token:       HackerOne API token (username:token format)
            program_handle: HackerOne program handle (e.g. "twitter")

        Returns:
            dict with h1_report_id and report_url on success
        """
        if not _HAS_AIOHTTP:
            raise RuntimeError("aiohttp required for HackerOne export")


        async with self._db.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise ValueError(f"Finding {finding_id} not found in database")

        finding = _row_to_finding(row)
        payload = self._format_h1_payload(finding, program_handle)



        if ":" in h1_token:
            username, api_token = h1_token.split(":", 1)
        else:
            username, api_token = "user", h1_token

        auth = _aiohttp.BasicAuth(username, api_token)
        headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }

        async with _aiohttp.ClientSession(auth=auth) as session:
            async with session.post(
                _H1_REPORTS_URL,
                json=payload,
                headers=headers,
                timeout=_aiohttp.ClientTimeout(total=30),
            ) as resp:
                body = await resp.json()

                if resp.status in (200, 201):
                    report_id  = str(body.get("data", {}).get("id", ""))
                    report_url = f"https://hackerone.com/reports/{report_id}"


                    await self.mark_reported(finding_id, h1_report_id=report_id)

                    return {
                        "success":    True,
                        "report_id":  report_id,
                        "report_url": report_url,
                    }
                else:
                    error_detail = body.get("errors", body)
                    raise RuntimeError(
                        f"HackerOne API error {resp.status}: {error_detail}"
                    )

    def _format_h1_payload(self, finding: DBFinding, program_handle: str) -> dict:
        """Format a finding as a HackerOne v1 API report payload."""
        sev_map = {
            "CRITICAL": "critical",
            "HIGH":     "high",
            "MEDIUM":   "medium",
            "LOW":      "low",
            "INFO":     "informative",
        }
        h1_severity = sev_map.get(finding.severity.upper(), "medium")


        vuln_info = "\n".join(filter(None, [
            finding.description,
            "",
            "**Evidence:**",
            f"```\n{finding.evidence}\n```" if finding.evidence else "",
            "",
            "**Reproduction:**",
            f"```bash\n{finding.verified_curl}\n```" if finding.verified_curl else "",
            "",
            "**Recommendation:**",
            finding.recommendation,
            "",
            f"**References:** {finding.cwe} | {finding.owasp}",
        ]))

        return {
            "data": {
                "type": "report",
                "attributes": {
                    "title":     finding.title,
                    "vulnerability_information": vuln_info,
                    "severity_rating": h1_severity,
                    "impact": (
                        f"CVSS: {finding.cvss}. "
                        f"Confirmed: {'Yes' if finding.confirmed else 'No'}. "
                        f"Confidence: {finding.confidence}%."
                    ),
                },
                "relationships": {
                    "program": {
                        "data": {
                            "type": "program",
                            "attributes": {"handle": program_handle},
                        }
                    }
                },
            }
        }

    def format_h1_markdown(self, finding: DBFinding) -> str:
        """
        Format a finding as copy-paste HackerOne markdown.
        Use this when you want to review before submitting.
        """
        lines = [
            f"# {finding.title}",
            "",
            f"**Severity:** {finding.severity}",
            f"**CVSS:** {finding.cvss}",
            f"**Endpoint:** `{finding.endpoint}`",
            f"**Confidence:** {finding.confidence}%"
            + (" ✓ CONFIRMED" if finding.confirmed else ""),
            "",
            "## Description",
            "",
            finding.description,
            "",
            "## Evidence",
            "",
            f"```\n{finding.evidence}\n```",
            "",
        ]

        if finding.verified_curl:
            lines += [
                "## Reproduction",
                "",
                "```bash",
                finding.verified_curl,
                "```",
                "",
            ]

        lines += [
            "## Recommendation",
            "",
            finding.recommendation,
            "",
            "## References",
            "",
            f"- {finding.cwe}",
            f"- {finding.owasp}",
        ]
        return "\n".join(lines)



    async def get_stats(self, program: str = "") -> DBStats:
        """Get aggregated statistics from the database."""
        where  = "WHERE program = ?" if program else ""
        params = (program,) if program else ()

        stats = DBStats(by_severity={}, by_program={}, by_category={},
                        top_endpoints=[], recent_findings=[])


        async with self._db.execute(
            f"SELECT COUNT(*), SUM(bounty_amount) FROM findings {where}", params
        ) as cur:
            row = await cur.fetchone()
            stats.total_findings = row[0] or 0
            stats.total_bounty   = float(row[1] or 0.0)

        async with self._db.execute(
            f"SELECT COUNT(*) FROM findings {where} AND confirmed=1".replace(
                "WHERE AND", "WHERE"
            ) if program else
            "SELECT COUNT(*) FROM findings WHERE confirmed=1",
            params if program else (),
        ) as cur:
            row = await cur.fetchone()
            stats.total_confirmed = row[0] or 0

        async with self._db.execute(
            f"SELECT COUNT(*) FROM findings {where} AND status='reported'".replace(
                "WHERE AND", "WHERE"
            ) if program else
            "SELECT COUNT(*) FROM findings WHERE status='reported'",
            params if program else (),
        ) as cur:
            row = await cur.fetchone()
            stats.total_reported = row[0] or 0


        async with self._db.execute(
            f"SELECT severity, COUNT(*) FROM findings {where} "
            "GROUP BY severity ORDER BY COUNT(*) DESC",
            params,
        ) as cur:
            rows = await cur.fetchall()
            stats.by_severity = {row[0]: row[1] for row in rows}


        async with self._db.execute(
            "SELECT program, COUNT(*) FROM findings "
            "GROUP BY program ORDER BY COUNT(*) DESC LIMIT 10"
        ) as cur:
            rows = await cur.fetchall()
            stats.by_program = {row[0]: row[1] for row in rows}


        async with self._db.execute(
            f"SELECT category, COUNT(*) FROM findings {where} "
            "GROUP BY category ORDER BY COUNT(*) DESC LIMIT 10",
            params,
        ) as cur:
            rows = await cur.fetchall()
            stats.by_category = {row[0]: row[1] for row in rows}


        recent = await self.get_findings(program=program, limit=5)
        stats.recent_findings = recent

        return stats

    def print_stats(self, stats: DBStats):
        """Print statistics to terminal."""
        print(f"\n{'─'*50}")
        print(f" BLFinder Database Statistics")
        print(f"{'─'*50}")
        print(f" Total findings   : {stats.total_findings}")
        print(f" Confirmed        : {stats.total_confirmed}")
        print(f" Reported         : {stats.total_reported}")
        print(f" Total bounty     : ${stats.total_bounty:.2f}")
        print()

        if stats.by_severity:
            print(" By Severity:")
            for sev, count in stats.by_severity.items():
                print(f"   {sev:<12} {count}")

        if stats.by_program:
            print("\n By Program:")
            for prog, count in list(stats.by_program.items())[:5]:
                prog_display = prog or "(untagged)"
                print(f"   {prog_display:<20} {count}")

        if stats.recent_findings:
            print("\n Recent Findings:")
            for f in stats.recent_findings[:3]:
                print(f"   [{f.severity}] {f.title[:50]}")
        print(f"{'─'*50}\n")

    def print_findings(self, findings: list[DBFinding]):
        """Print a list of findings to terminal."""
        if not findings:
            print("No findings found.")
            return
        print(f"\n{len(findings)} finding(s):\n")
        for i, f in enumerate(findings, 1):
            conf = f"({f.confidence}%)" if f.confidence else ""
            confirmed = " ✓" if f.confirmed else ""
            print(f"{i:>3}. [{f.severity}]{confirmed} {f.title} {conf}")
            print(f"     Endpoint: {f.endpoint}")
            print(f"     Status:   {f.status}")
            if f.h1_report_id:
                print(f"     H1 Report: https://hackerone.com/reports/{f.h1_report_id}")
            print()




def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _make_dedup_hash(finding) -> str:
    """SHA256 hash of (endpoint + vulnerability_type + parameter)."""
    endpoint = getattr(finding, "endpoint", "") or ""
    category = getattr(finding, "category", "") or ""
    parameter = getattr(finding, "parameter", "") or ""
    raw = f"{endpoint.lower()}|{category.lower()}|{parameter.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _row_to_finding(row) -> DBFinding:
    """Convert a database row to a DBFinding dataclass."""
    return DBFinding(
        id=row["id"],
        title=row["title"],
        severity=row["severity"],
        category=row["category"] or "",
        endpoint=row["endpoint"] or "",
        parameter=row["parameter"] or "",
        evidence=row["evidence"] or "",
        description=row["description"] or "",
        recommendation=row["recommendation"] or "",
        cwe=row["cwe"] or "",
        cvss=float(row["cvss"] or 0.0),
        owasp=row["owasp"] or "",
        confirmed=bool(row["confirmed"]),
        confidence=int(row["confidence"] or 0),
        dedup_hash=row["dedup_hash"] or "",
        program=row["program"] or "",
        scan_id=row["scan_id"],
        reported_at=row["reported_at"],
        h1_report_id=row["h1_report_id"],
        bounty_amount=float(row["bounty_amount"] or 0.0),
        status=row["status"] or "new",
        created_at=row["created_at"] or "",
        verified_curl=row["verified_curl"] or "",
    )
