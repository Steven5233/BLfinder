"""
BLFinder — Scan Checkpoint

Persists per-endpoint scan progress and findings to disk INCREMENTALLY,
as each endpoint finishes — not just once at the very end of the scan.

Why this exists: previously, `findings` only reached the database/report
generators after `scanner.run_all_modules()` returned in full. If the scan
was interrupted (Ctrl+C, dropped connection, phone locked mid-scan on
Termux, OOM-killed process, etc.) partway through a large endpoint list,
every finding discovered up to that point — and the fact that those
endpoints had already been checked — was silently lost. The next run
started from endpoint #1 again with no memory of any of it.

This module gives BLFinder a small, atomic, on-disk record of:
  - which (url, method) endpoints have already been fully checked
  - the findings produced by each of them so far

`--resume` (wired in blfinder.py) loads this file, skips already-completed
endpoints, and merges the previously-found findings into the final report.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import time
from dataclasses import dataclass, field


def checkpoint_path_for(target_url: str, output_dir: str = ".") -> str:
    """Deterministic default path so a repeat scan of the same target
    against the same output dir naturally finds its own checkpoint."""
    h = hashlib.sha256(target_url.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return os.path.join(output_dir, f".blfinder_checkpoint_{h}.pkl")


@dataclass
class ScanCheckpoint:
    target_url: str
    path:       str
    completed:  set   = field(default_factory=set)   
    findings:   list  = field(default_factory=list)  
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    total_endpoints: int = 0



    def mark_done(self, url: str, method: str, findings: list | None = None) -> None:
        """Record one endpoint as fully checked and persist immediately."""
        self.completed.add((url, method))
        if findings:
            self.findings.extend(findings)
        self.updated_at = time.time()
        self.save()

    def add_findings(self, findings: list) -> None:
        """For non-per-endpoint phases (flow attacks, OAuth, phase4, etc.) —
        checkpoint them too so they aren't lost if the scan is interrupted
        during the (usually much longer) endpoint loop that follows."""
        if findings:
            self.findings.extend(findings)
            self.updated_at = time.time()
            self.save()

    def is_done(self, url: str, method: str) -> bool:
        return (url, method) in self.completed



    def save(self) -> None:
        """Atomic write (write to temp file, then os.replace) so a crash or
        kill signal mid-write can never corrupt the checkpoint — worst case
        you lose only the most recent, not-yet-flushed update."""
        try:
            tmp_path = f"{self.path}.tmp"
            with open(tmp_path, "wb") as fh:
                pickle.dump(self, fh, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp_path, self.path)
        except Exception:



            pass

    @classmethod
    def load(cls, path: str) -> "ScanCheckpoint":
        with open(path, "rb") as fh:
            obj = pickle.load(fh)
        if not isinstance(obj, cls):
            raise ValueError("Checkpoint file is not a valid ScanCheckpoint")
        return obj

    @classmethod
    def load_or_create(cls, path: str, target_url: str) -> "ScanCheckpoint":
        if os.path.exists(path):
            try:
                ckpt = cls.load(path)


                if ckpt.target_url == target_url:
                    return ckpt
            except Exception:
                pass
        return cls(target_url=target_url, path=path)

    def clear(self) -> None:
        """Delete the checkpoint file — called once a scan completes fully,
        so a clean run doesn't leave stale resume state behind."""
        try:
            os.remove(self.path)
        except OSError:
            pass



    def summary(self) -> str:
        age = time.time() - self.updated_at
        return (
            f"{len(self.completed)} endpoint(s) already checked, "
            f"{len(self.findings)} finding(s) carried over "
            f"(last updated {age:.0f}s ago)"
        )
