"""
BLFinder Phase 5 — core/tui/live_dashboard.py
Live Terminal Dashboard (Termux-Optimized)

Shows scan progress, live findings, and request statistics in real time.
Uses Python curses with a narrow-viewport layout optimized for phones.

Layout (fits 390px Termux screen, ~45 chars wide):
  ┌─ BLFinder v3.1 ────────────────────┐
  │ Target: api.target.com   00:04:32  │
  │ ████████░░ 18/22 endpoints         │
  ├────────────────────────────────────┤
  │ [CRIT] IDOR /orders/{id} ✓        │
  │ [HIGH] BOPLA expand=all            │
  │ [MED ] Enum timing 0.34s           │
  ├────────────────────────────────────┤
  │ Req:847 | 429:3 | Found:3 | Q:4   │
  └────────────────────────────────────┘

Controls: p=pause  v=verbose  q=quit+report

Falls back to enhanced ANSI output if curses is unavailable.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

try:
    import curses
    _HAS_CURSES = True
except ImportError:
    _HAS_CURSES = False


# ── ANSI colors (Termux-compatible) ──────────────────────────────────────────
_ANSI = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[1;33m",
    "MEDIUM":   "\033[1;34m",
    "LOW":      "\033[1;32m",
    "INFO":     "\033[1;36m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "GREEN":    "\033[1;32m",
    "CYAN":     "\033[1;36m",
    "BAR_FILL": "\033[42m",
    "BAR_EMPTY":"\033[100m",
}


@dataclass
class DashboardState:
    """Shared mutable state between scanner and dashboard."""
    # Progress
    total_endpoints:   int = 0
    scanned_endpoints: int = 0
    current_endpoint:  str = ""
    scan_start_time:   float = field(default_factory=time.time)

    # Stats
    total_requests:    int = 0
    total_429s:        int = 0
    total_findings:    int = 0
    queue_size:        int = 0

    # Findings (recent N shown)
    findings:          list[dict] = field(default_factory=list)   # {title, severity, confirmed}
    max_findings_shown: int = 5

    # Control
    paused:            bool = False
    verbose:           bool = False
    quit_requested:    bool = False
    report_on_quit:    bool = True

    # Target
    target:            str = ""

    @property
    def elapsed(self) -> str:
        secs = int(time.time() - self.scan_start_time)
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        if h:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    @property
    def progress_pct(self) -> float:
        if self.total_endpoints == 0:
            return 0.0
        return min(1.0, self.scanned_endpoints / self.total_endpoints)

    def add_finding(self, title: str, severity: str, confirmed: bool = False):
        self.findings.append({
            "title":     title,
            "severity":  severity,
            "confirmed": confirmed,
        })
        self.total_findings = len(self.findings)


class LiveDashboard:
    """
    Live terminal dashboard for BLFinder scans.

    Usage:
        state    = DashboardState(target="api.target.com", total_endpoints=22)
        dashboard = LiveDashboard(state)

        # Start dashboard in background
        asyncio.create_task(dashboard.run())

        # From scanner, update state:
        state.scanned_endpoints += 1
        state.add_finding("IDOR found", "CRITICAL", confirmed=True)

        # Stop cleanly
        await dashboard.stop()
    """

    def __init__(
        self,
        state:           DashboardState,
        on_quit:         Callable | None = None,
        refresh_ms:      int = 500,
        force_ansi:      bool = False,
    ):
        self.state       = state
        self.on_quit     = on_quit
        self.refresh_ms  = refresh_ms
        self._use_curses = _HAS_CURSES and not force_ansi and _has_tty()
        self._running    = False
        self._stdscr     = None

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self):
        """Start the dashboard. Returns when quit is requested."""
        self._running = True

        if self._use_curses:
            await self._run_curses()
        else:
            await self._run_ansi()

    async def stop(self):
        """Stop the dashboard gracefully."""
        self._running = False
        self.state.quit_requested = True

    # ── Curses mode ───────────────────────────────────────────────────────────

    async def _run_curses(self):
        """Run the dashboard using Python curses."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._curses_main)

    def _curses_main(self):
        """Blocking curses main loop (runs in executor)."""
        try:
            curses.wrapper(self._curses_loop)
        except Exception as e:
            # Fall back to ANSI if curses fails
            self._use_curses = False

    def _curses_loop(self, stdscr):
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(self.refresh_ms)

        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED,     -1)  # CRITICAL
        curses.init_pair(2, curses.COLOR_YELLOW,  -1)  # HIGH
        curses.init_pair(3, curses.COLOR_BLUE,    -1)  # MEDIUM
        curses.init_pair(4, curses.COLOR_GREEN,   -1)  # LOW/confirmed
        curses.init_pair(5, curses.COLOR_CYAN,    -1)  # info/header
        curses.init_pair(6, curses.COLOR_WHITE,   -1)  # normal
        curses.init_pair(7, curses.COLOR_MAGENTA, -1)  # accent

        while self._running and not self.state.quit_requested:
            try:
                self._draw_curses(stdscr)

                # Non-blocking key read
                key = stdscr.getch()
                if key != -1:
                    self._handle_key(chr(key) if 0 < key < 256 else "")

            except curses.error:
                pass
            except KeyboardInterrupt:
                self.state.quit_requested = True
                break

            time.sleep(self.refresh_ms / 1000)

    def _draw_curses(self, stdscr):
        """Render the full dashboard."""
        try:
            height, width = stdscr.getmaxyx()
            stdscr.erase()

            w = min(width, 60)
            state = self.state

            row = 0

            # ── Header ────────────────────────────────────────────────────────
            header = f" BLFinder v3.1"
            stdscr.addstr(row, 0, "─" * w, curses.color_pair(5))
            row += 1
            stdscr.addstr(row, 0, header[:w], curses.color_pair(7) | curses.A_BOLD)
            if width > len(header) + 10:
                elapsed_str = f" {state.elapsed} "
                stdscr.addstr(row, w - len(elapsed_str), elapsed_str, curses.color_pair(6))
            row += 1

            # Target
            target_str = f" Target: {state.target}"[:w-1]
            stdscr.addstr(row, 0, target_str, curses.color_pair(5))
            row += 1

            # Progress bar
            bar_width = max(10, w - 20)
            filled    = int(bar_width * state.progress_pct)
            bar       = "█" * filled + "░" * (bar_width - filled)
            prog_str  = f" {state.scanned_endpoints}/{state.total_endpoints}"
            stdscr.addstr(row, 0, f" [{bar}]{prog_str}", curses.color_pair(4))
            row += 1

            # Current endpoint
            ep_str = f" ⟳ {state.current_endpoint}"
            stdscr.addstr(row, 0, ep_str[:w-1], curses.color_pair(6) | curses.A_DIM)
            row += 1

            # Divider
            stdscr.addstr(row, 0, "─" * w, curses.color_pair(5))
            row += 1

            # ── Findings ──────────────────────────────────────────────────────
            if not state.findings:
                stdscr.addstr(row, 0, " No findings yet...", curses.color_pair(6) | curses.A_DIM)
                row += 1
            else:
                recent = state.findings[-state.max_findings_shown:]
                for f in recent:
                    sev       = f["severity"]
                    confirmed = " ✓" if f["confirmed"] else ""
                    color_pair = {
                        "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4,
                    }.get(sev, 6)
                    badge   = f"[{sev[:4]}]"
                    title   = f["title"]
                    line    = f" {badge}{confirmed} {title}"[:w-1]
                    try:
                        stdscr.addstr(row, 0, line, curses.color_pair(color_pair))
                    except curses.error:
                        pass
                    row += 1
                    if row >= height - 3:
                        break

            # Fill remaining space to divider
            while row < height - 3:
                try:
                    stdscr.addstr(row, 0, " " * w)
                except curses.error:
                    pass
                row += 1

            # ── Stats bar ─────────────────────────────────────────────────────
            row = height - 3
            stdscr.addstr(row, 0, "─" * w, curses.color_pair(5))
            row += 1
            stats_str = (
                f" Req:{state.total_requests}"
                f" | 429:{state.total_429s}"
                f" | Found:{state.total_findings}"
                f" | Q:{state.queue_size}"
            )
            stdscr.addstr(row, 0, stats_str[:w-1], curses.color_pair(6))
            row += 1

            # Controls
            pause_label = "[R]esume" if state.paused else "[P]ause"
            ctrl_str = f" {pause_label} [V]erbose [Q]uit"
            if state.paused:
                ctrl_str = " ⏸ PAUSED " + ctrl_str
            try:
                stdscr.addstr(row, 0, ctrl_str[:w-1], curses.color_pair(5) | curses.A_DIM)
            except curses.error:
                pass

            stdscr.refresh()

        except curses.error:
            pass

    def _handle_key(self, key: str):
        key = key.lower()
        if key == "p":
            self.state.paused = not self.state.paused
        elif key == "r":
            self.state.paused = False
        elif key == "v":
            self.state.verbose = not self.state.verbose
        elif key == "q":
            self.state.quit_requested = True
            self._running = False

    # ── ANSI fallback mode ────────────────────────────────────────────────────

    async def _run_ansi(self):
        """
        Enhanced ANSI progress output — used when curses is unavailable.
        Works in any terminal including Termux without tty.
        """
        last_finding_count = 0
        spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spin_idx = 0

        while self._running and not self.state.quit_requested:
            state = self.state

            # Clear line and print progress
            pct   = int(state.progress_pct * 20)
            bar   = "█" * pct + "░" * (20 - pct)
            spin  = spinner_chars[spin_idx % len(spinner_chars)]
            spin_idx += 1

            line = (
                f"\r{_ANSI['DIM']}{spin}{_ANSI['RESET']} "
                f"[{_ANSI['GREEN']}{bar}{_ANSI['RESET']}] "
                f"{state.scanned_endpoints}/{state.total_endpoints} "
                f"| Found: {_ANSI['BOLD']}{state.total_findings}{_ANSI['RESET']}"
                f" | {state.elapsed}"
            )
            sys.stdout.write(line)
            sys.stdout.flush()

            # Print new findings
            if len(state.findings) > last_finding_count:
                new_findings = state.findings[last_finding_count:]
                for f in new_findings:
                    sev   = f["severity"]
                    color = _ANSI.get(sev, _ANSI["RESET"])
                    conf  = f"{_ANSI['GREEN']} ✓ CONFIRMED{_ANSI['RESET']}" if f["confirmed"] else ""
                    print(
                        f"\r\n{color}[{sev}]{_ANSI['RESET']}{conf} "
                        f"{f['title'][:60]}"
                    )
                last_finding_count = len(state.findings)

            await asyncio.sleep(self.refresh_ms / 1000)

        # Final newline
        print()

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self):
        self._task = asyncio.create_task(self.run())
        return self

    async def __aexit__(self, *args):
        await self.stop()
        if hasattr(self, "_task"):
            try:
                await asyncio.wait_for(self._task, timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_tty() -> bool:
    """Check if we're running in an interactive terminal."""
    return sys.stdout.isatty() and sys.stdin.isatty()


def create_dashboard(
    target: str,
    total_endpoints: int,
    verbose: bool = False,
    force_ansi: bool = False,
) -> tuple[LiveDashboard, DashboardState]:
    """
    Convenience factory — create dashboard + state in one call.

    Returns:
        (dashboard, state) — start dashboard with asyncio.create_task(dashboard.run())
    """
    state = DashboardState(
        target=target,
        total_endpoints=total_endpoints,
        verbose=verbose,
    )
    dashboard = LiveDashboard(state, force_ansi=force_ansi)
    return dashboard, state
