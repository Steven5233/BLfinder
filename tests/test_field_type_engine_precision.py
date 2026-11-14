from blfinder.core.intelligence.field_type_engine import (
    FieldType,
    is_minor_unit_field,
    rescale_minor_unit_payload,
    weaker_currency_candidates,
    generate_precision_payloads,
)


def test_is_minor_unit_field_matches_cents_suffix():
    assert is_minor_unit_field("amount_cents") is True
    assert is_minor_unit_field("price_minor") is True


def test_is_minor_unit_field_rejects_plain_amount():
    assert is_minor_unit_field("amount") is False


def test_rescale_minor_unit_payload_int():
    assert rescale_minor_unit_payload(10000) == 100


def test_rescale_minor_unit_payload_float():
    assert rescale_minor_unit_payload(1999.0) == 19.99


def test_rescale_minor_unit_payload_rejects_non_numeric():
    assert rescale_minor_unit_payload("not-a-number") is None


def test_weaker_currency_candidates_known():
    assert "ngn" in weaker_currency_candidates("usd")


def test_weaker_currency_candidates_unknown_returns_empty():
    assert weaker_currency_candidates("xau") == []


def test_generate_precision_payloads_float_includes_sub_cent():
    payloads = generate_precision_payloads(FieldType.FLOAT, 49.99)
    assert 0.0049 in payloads
    assert all(p >= 0 for p in payloads)


def test_generate_precision_payloads_monetary_string():
    payloads = generate_precision_payloads(FieldType.MONETARY_STRING, "49.99")
    assert "0.004" in payloads


def test_generate_precision_payloads_unsupported_type_returns_empty():
    assert generate_precision_payloads(FieldType.BOOLEAN, True) == []
