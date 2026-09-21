from blfinder.core.analysis.semantic_diff import SemanticDiff


def test_incidental_denied_wording_does_not_suppress_real_difference():
    baseline = "<html><body>Access to this page is restricted.</body></html>"
    tampered = (
        "<html><body>Claim history: 3 approved, 1 denied, "
        "balance available: $4,250.00, account owner: Jane Doe</body></html>"
    )
    result = SemanticDiff.compare(baseline, tampered)
    assert result.is_different is True


def test_genuine_rejection_with_no_success_content_suppressed():
    baseline = "<html><body>Welcome to your dashboard</body></html>"
    tampered = "<html><body>Error: request denied, forbidden</body></html>"
    result = SemanticDiff.compare(baseline, tampered)
    assert result.is_different is False
