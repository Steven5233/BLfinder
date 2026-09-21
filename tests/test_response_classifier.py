from blfinder.core.validation.response_classifier import ResponseClassifier, ResponseClass


def classify(status=200, body="", headers=None):
    return ResponseClassifier().classify("https://api.example.com/x", status, headers or {}, body)


def test_single_generic_phrase_does_not_trigger_waf_block():
    body = '{"error": "Access denied: you do not own this resource"}'
    result = classify(status=403, body=body)
    assert result.response_class != ResponseClass.WAF_BLOCK
    assert result.suppress_findings is False


def test_two_generic_phrases_do_trigger_waf_block():
    body = "Your request has triggered a security violation. Request blocked."
    result = classify(status=403, body=body)
    assert result.response_class == ResponseClass.WAF_BLOCK
    assert result.suppress_findings is True


def test_vendor_signature_alone_triggers_waf_block():
    body = "<title>Attention Required! | Cloudflare</title>"
    result = classify(status=403, body=body)
    assert result.response_class == ResponseClass.WAF_BLOCK
    assert result.suppress_findings is True
