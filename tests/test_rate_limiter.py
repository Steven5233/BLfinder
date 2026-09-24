import asyncio
import time

from blfinder.core.scanner import AdaptiveRateLimiter


def test_concurrent_callers_are_properly_spaced_not_bursted():
    async def worker(rl, url, results):
        t0 = time.monotonic()
        await rl.wait(url)
        results.append(time.monotonic() - t0)

    async def scenario():
        rl = AdaptiveRateLimiter(base_delay=0.05)
        results = []
        await asyncio.gather(*[worker(rl, "https://x.test/a", results) for _ in range(5)])
        return sorted(results)

    times = asyncio.run(scenario())
    # A burst (the bug) would cluster all 5 near t=0. Proper serialization
    # spaces them roughly base_delay apart, so the last caller should have
    # waited close to (n-1) * base_delay.
    assert times[-1] >= 0.05 * 3


def test_different_domains_do_not_block_each_other():
    async def scenario():
        rl = AdaptiveRateLimiter(base_delay=0.2)
        t0 = time.monotonic()
        await asyncio.gather(
            rl.wait("https://a.test/x"),
            rl.wait("https://b.test/x"),
            rl.wait("https://c.test/x"),
        )
        return time.monotonic() - t0

    elapsed = asyncio.run(scenario())
    assert elapsed < 0.15


def test_429_backoff_still_applies_after_fix():
    rl = AdaptiveRateLimiter(base_delay=0.3)
    rl.record("https://x.test/a", 429, 0.1)
    assert rl.delays["x.test"] > rl.base_delay
