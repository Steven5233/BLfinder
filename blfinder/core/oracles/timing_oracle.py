"""
BLFinder v3.0 — core/oracles/timing_oracle.py
Statistical Timing Oracle

Replaces the naive single-measurement timing check in v2.1 with a
statistically robust oracle. Uses multiple samples, removes outliers
from network jitter, and applies significance testing to only report
timing differences that are genuinely meaningful.

Detects:
- Account enumeration (valid vs invalid username timing)
- Blind SQL/NoSQL injection (sleep-based)
- Blind IDOR (server takes longer when it finds a real resource vs 404)
- Authentication bypass (token validation skipped = faster response)
"""

from __future__ import annotations

import asyncio
import statistics
import time
import math
from dataclasses import dataclass, field
from typing import Callable, Awaitable


@dataclass
class TimingResult:
    """Result of a timing oracle measurement."""

    samples_a: list[float] = field(default_factory=list)   
    samples_b: list[float] = field(default_factory=list)   


    mean_a: float = 0.0
    mean_b: float = 0.0
    median_a: float = 0.0
    median_b: float = 0.0
    stdev_a: float = 0.0
    stdev_b: float = 0.0
    delta: float = 0.0              
    delta_pct: float = 0.0          


    is_significant: bool = False    
    confidence: float = 0.0         
    effect_size: float = 0.0        
    p_value_approx: float = 1.0     


    interpretation: str = ""        
    fp_signals: list[str] = field(default_factory=list)


    min_delta_ms: float = 0.0       
    sample_count: int = 0


class TimingOracle:
    """
    Statistical timing oracle for detecting timing-based vulnerabilities.

    Key improvements over v2.1:
    - Multiple samples (default: 8 per condition)
    - Outlier removal using IQR method
    - Effect size calculation (Cohen's d)
    - Adaptive thresholds based on network variance
    - Automatic false positive suppression for high-variance networks

    Usage:
        oracle = TimingOracle(scanner)

        result = await oracle.compare(
            request_a=lambda: scanner._request("POST", url, json=body_valid),
            request_b=lambda: scanner._request("POST", url, json=body_invalid),
            description="valid vs invalid username",
            samples=8
        )

        if result.is_significant:
            # Real timing difference detected
    """


    MIN_DELTA_THRESHOLD = 0.100     


    MIN_EFFECT_SIZE = 0.8           


    MAX_CV_THRESHOLD = 0.5          

    def __init__(self, scanner=None):
        """
        Args:
            scanner: BLFScanner instance (for rate limiting). Can be None for standalone use.
        """
        self.scanner = scanner

    async def compare(
        self,
        request_a: Callable[[], Awaitable[tuple]],
        request_b: Callable[[], Awaitable[tuple]],
        description: str = "",
        samples: int = 8,
        min_delta_ms: float = None,
        interleave: bool = True,
    ) -> TimingResult:
        """
        Compare timing between two request types.

        Args:
            request_a: Async callable returning (status, headers, body, elapsed)
            request_b: Async callable returning the same
            description: Human-readable description of what A and B represent
            samples: Number of measurements per condition
            min_delta_ms: Override minimum delta threshold (milliseconds)
            interleave: If True, alternate A and B measurements to control for time drift

        Returns:
            TimingResult with full statistical analysis
        """
        result = TimingResult()
        result.sample_count = samples
        result.min_delta_ms = min_delta_ms or (self.MIN_DELTA_THRESHOLD * 1000)

        samples_a = []
        samples_b = []

        if interleave:

            for _ in range(samples):
                _, _, _, t = await request_a()
                samples_a.append(t)
                await asyncio.sleep(0.05)
                _, _, _, t = await request_b()
                samples_b.append(t)
                await asyncio.sleep(0.05)
        else:
            for _ in range(samples):
                _, _, _, t = await request_a()
                samples_a.append(t)
                await asyncio.sleep(0.05)
            for _ in range(samples):
                _, _, _, t = await request_b()
                samples_b.append(t)
                await asyncio.sleep(0.05)

        result.samples_a = samples_a
        result.samples_b = samples_b

        return self._analyze(result, description, min_delta_ms)

    async def measure_single(
        self,
        request_fn: Callable[[], Awaitable[tuple]],
        samples: int = 6,
    ) -> dict:
        """
        Measure timing statistics for a single request type.
        Useful for establishing a baseline before comparison.
        """
        timings = []
        for _ in range(samples):
            _, _, _, t = await request_fn()
            timings.append(t)
            await asyncio.sleep(0.05)

        cleaned = self._remove_outliers(timings)
        return {
            "mean": statistics.mean(cleaned) if cleaned else 0.0,
            "median": statistics.median(cleaned) if cleaned else 0.0,
            "stdev": statistics.stdev(cleaned) if len(cleaned) > 1 else 0.0,
            "min": min(cleaned) if cleaned else 0.0,
            "max": max(cleaned) if cleaned else 0.0,
            "samples": timings,
            "cleaned_samples": cleaned,
        }

    async def detect_sleep_injection(
        self,
        base_request: Callable[[], Awaitable[tuple]],
        sleep_request: Callable[[], Awaitable[tuple]],
        expected_sleep_seconds: float = 5.0,
        samples: int = 3,
    ) -> TimingResult:
        """
        Detect sleep-based injection (SQLi, NoSQLi, SSTI, etc.)
        Tests if a payload that should cause N seconds of sleep actually does.
        """
        result = TimingResult()
        result.sample_count = samples

        base_times = []
        sleep_times = []

        for _ in range(samples):
            _, _, _, t = await base_request()
            base_times.append(t)
            await asyncio.sleep(0.1)

        for _ in range(samples):
            _, _, _, t = await sleep_request()
            sleep_times.append(t)
            await asyncio.sleep(0.1)

        result.samples_a = base_times
        result.samples_b = sleep_times

        base_clean = self._remove_outliers(base_times)
        sleep_clean = self._remove_outliers(sleep_times)

        if not base_clean or not sleep_clean:
            result.interpretation = "Insufficient samples for analysis"
            return result

        result.mean_a = statistics.mean(base_clean)
        result.mean_b = statistics.mean(sleep_clean)
        result.delta = result.mean_b - result.mean_a


        if result.delta >= expected_sleep_seconds * 0.8:
            result.is_significant = True
            result.confidence = min(1.0, result.delta / expected_sleep_seconds)
            result.interpretation = (
                f"Sleep injection confirmed: response delayed by {result.delta:.2f}s "
                f"(expected {expected_sleep_seconds}s)"
            )
        else:
            result.interpretation = (
                f"No sleep delay detected. Delta={result.delta:.3f}s, "
                f"expected >={expected_sleep_seconds * 0.8:.1f}s"
            )

        return result



    def _analyze(self, result: TimingResult, description: str, min_delta_ms: float | None) -> TimingResult:
        """Run full statistical analysis on collected timing samples."""


        clean_a = self._remove_outliers(result.samples_a)
        clean_b = self._remove_outliers(result.samples_b)

        if len(clean_a) < 2 or len(clean_b) < 2:
            result.interpretation = "Too few valid samples after outlier removal"
            result.fp_signals.append("Insufficient clean samples — network may be too unstable")
            return result


        result.mean_a = statistics.mean(clean_a)
        result.mean_b = statistics.mean(clean_b)
        result.median_a = statistics.median(clean_a)
        result.median_b = statistics.median(clean_b)
        result.stdev_a = statistics.stdev(clean_a) if len(clean_a) > 1 else 0.0
        result.stdev_b = statistics.stdev(clean_b) if len(clean_b) > 1 else 0.0
        result.delta = result.mean_b - result.mean_a
        result.delta_pct = (result.delta / result.mean_a * 100) if result.mean_a > 0 else 0.0


        cv_a = result.stdev_a / result.mean_a if result.mean_a > 0 else 0.0
        cv_b = result.stdev_b / result.mean_b if result.mean_b > 0 else 0.0
        avg_cv = (cv_a + cv_b) / 2

        if avg_cv > self.MAX_CV_THRESHOLD:
            result.fp_signals.append(
                f"High network variance (CV={avg_cv:.0%}) — timing oracle unreliable on this connection. "
                "Use a stable network or increase samples."
            )


        pooled_std = math.sqrt((result.stdev_a ** 2 + result.stdev_b ** 2) / 2)
        result.effect_size = abs(result.delta) / pooled_std if pooled_std > 0 else 0.0


        result.p_value_approx = self._welch_p_value(clean_a, clean_b)


        threshold_s = (min_delta_ms or result.min_delta_ms) / 1000


        delta_significant = abs(result.delta) >= threshold_s
        effect_significant = result.effect_size >= self.MIN_EFFECT_SIZE
        p_significant = result.p_value_approx < 0.05

        result.is_significant = (
            delta_significant and
            effect_significant and
            p_significant and
            avg_cv <= self.MAX_CV_THRESHOLD
        )


        signals = [
            min(1.0, abs(result.delta) / (threshold_s * 3)),      
            min(1.0, result.effect_size / (self.MIN_EFFECT_SIZE * 2)),  
            max(0.0, 1.0 - result.p_value_approx * 10),            
            max(0.0, 1.0 - avg_cv / self.MAX_CV_THRESHOLD),        
        ]
        result.confidence = statistics.mean(signals)


        direction = "slower" if result.delta > 0 else "faster"
        result.interpretation = (
            f"{description}: B is {abs(result.delta)*1000:.0f}ms {direction} than A "
            f"(effect_size={result.effect_size:.2f}, p≈{result.p_value_approx:.3f})"
        )

        if not result.is_significant:
            reasons = []
            if not delta_significant:
                reasons.append(f"delta {abs(result.delta)*1000:.0f}ms < threshold {threshold_s*1000:.0f}ms")
            if not effect_significant:
                reasons.append(f"effect_size {result.effect_size:.2f} < {self.MIN_EFFECT_SIZE}")
            if not p_significant:
                reasons.append(f"p={result.p_value_approx:.3f} >= 0.05")
            if avg_cv > self.MAX_CV_THRESHOLD:
                reasons.append(f"network variance too high (CV={avg_cv:.0%})")
            result.fp_signals.append(f"Not significant: {', '.join(reasons)}")

        return result

    def _remove_outliers(self, samples: list[float]) -> list[float]:
        """
        Remove outliers using the IQR method.
        Removes values more than 1.5 × IQR below Q1 or above Q3.
        Also removes the single fastest and slowest values (Winsorize).
        """
        if len(samples) < 4:
            return samples[:]

        sorted_s = sorted(samples)


        trimmed = sorted_s[1:-1]


        n = len(trimmed)
        q1 = trimmed[n // 4]
        q3 = trimmed[(3 * n) // 4]
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr

        cleaned = [s for s in trimmed if lower <= s <= upper]
        return cleaned if len(cleaned) >= 2 else trimmed

    def _welch_p_value(self, a: list[float], b: list[float]) -> float:
        """
        Compute approximate p-value using Welch's t-test.
        Returns a value in [0, 1]; lower = more significant.
        """
        if len(a) < 2 or len(b) < 2:
            return 1.0

        mean_a = statistics.mean(a)
        mean_b = statistics.mean(b)
        var_a = statistics.variance(a)
        var_b = statistics.variance(b)
        n_a = len(a)
        n_b = len(b)

        se = math.sqrt(var_a / n_a + var_b / n_b)
        if se == 0:
            return 1.0 if mean_a == mean_b else 0.0

        t_stat = abs(mean_a - mean_b) / se


        dof = (var_a / n_a + var_b / n_b) ** 2 / (
            (var_a / n_a) ** 2 / (n_a - 1) + (var_b / n_b) ** 2 / (n_b - 1)
        )



        p = self._t_survival(t_stat, dof)
        return min(1.0, max(0.0, p))

    def _t_survival(self, t: float, df: float) -> float:
        """
        Approximate two-tailed p-value for t-distribution.
        Uses a fast approximation valid for df > 5.
        """
        if df <= 0 or t <= 0:
            return 1.0


        if df > 30:

            z = t
            p = 2.0 * (1.0 - self._normal_cdf(z))
            return max(0.0, min(1.0, p))


        x = df / (df + t * t)

        p = self._beta_approx(x, df / 2.0, 0.5)
        return max(0.0, min(1.0, p))

    def _normal_cdf(self, x: float) -> float:
        """Approximate CDF of standard normal distribution."""

        t = 1.0 / (1.0 + 0.2316419 * abs(x))
        poly = t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))))
        phi = (1.0 / math.sqrt(2 * math.pi)) * math.exp(-0.5 * x * x)
        cdf = 1.0 - phi * poly
        return cdf if x >= 0 else 1.0 - cdf

    def _beta_approx(self, x: float, a: float, b: float) -> float:
        """Rough approximation of regularized incomplete beta function."""
        if x <= 0:
            return 0.0
        if x >= 1:
            return 1.0

        try:
            log_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
            log_x = a * math.log(x) + b * math.log(1 - x) - log_beta
            return min(1.0, math.exp(log_x) / a)
        except (ValueError, OverflowError):
            return 0.5
