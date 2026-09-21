from blfinder.core.discovery.layer5_dedup.soft404_filter import Soft404Filter, Soft404Profile


def test_real_response_mentioning_404_is_not_flagged_by_phrase_oracle():
    f = Soft404Filter()
    profile = Soft404Profile(domain="api.example.com")
    profile.canary_error_phrase = "not found"
    profile.built = True
    f._profiles["api.example.com"] = profile

    body = '{"order_id": 404, "product": "Widget #404", "status": "shipped"}'
    result = f.check("https://api.example.com/orders/404", 200, body)
    assert result.is_soft_404 is False


def test_genuine_soft_404_phrase_still_caught():
    f = Soft404Filter()
    profile = Soft404Profile(domain="api.example.com")
    profile.canary_error_phrase = "resource not found"
    profile.built = True
    f._profiles["api.example.com"] = profile

    body = '{"message": "resource not found for this id"}'
    result = f.check("https://api.example.com/orders/999999", 200, body)
    assert result.is_soft_404 is True
