import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "blfinder"))

from core.intelligence.platform_profiler import PlatformProfiler


def profiler():
    return PlatformProfiler()


def test_generic_headers_and_paths_do_not_misclassify_as_stripe():
    result = profiler().profile(
        "https://api.example-widgetshop.com/v1/customers/42",
        {"Request-Id": "corr-abc-123", "Content-Type": "application/json"},
        '{"id": 42, "name": "jane"}',
        ["/v1/customers", "/v1/subscriptions"],
    )
    assert result.known_platform != "STRIPE"


def test_header_value_mismatch_does_not_score():
    result = profiler().profile(
        "https://api.example-widgetshop.com/anything",
        {"Request-Id": "not-a-stripe-style-id"},
        "",
        [],
    )
    assert result.known_platform != "STRIPE"


def test_genuine_stripe_signals_still_detected_with_full_confidence():
    result = profiler().profile(
        "https://api.stripe.com/v1/charges",
        {"Stripe-Version": "2022-11-15", "Request-Id": "req_abc123"},
        '{"object": "charge", "livemode": false}',
        ["/v1/charges", "/v1/customers"],
    )
    assert result.known_platform == "STRIPE"
    assert result.confidence == 100


def test_host_match_alone_is_sufficient_strong_signal():
    result = profiler().profile(
        "https://api.spotify.com/v1/me", {}, "", []
    )
    assert result.known_platform == "SPOTIFY"
