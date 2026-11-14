import types

import pytest

from blfinder.core.modules.numeric_precision import NumericPrecisionScanner


def make_scanner():
    fake_scanner = types.SimpleNamespace(
        config=types.SimpleNamespace(verbose=False),
        _request=None,
    )
    return NumericPrecisionScanner(fake_scanner)


def test_finds_nested_price_field():
    scanner = make_scanner()
    body = {"order": {"amount": 49.99, "currency": "usd"}}
    fields = scanner._find_fields(body)
    paths = [f["path"] for f in fields]
    assert "order.amount" in paths


def test_ignores_non_price_numeric_fields():
    scanner = make_scanner()
    body = {"page": 1, "limit": 20}
    assert scanner._find_fields(body) == []


def test_finds_fields_inside_lists():
    scanner = make_scanner()
    body = {"items": [{"price": 10.0}, {"price": 20.0}]}
    fields = scanner._find_fields(body)
    paths = [f["path"] for f in fields]
    assert "items[0].price" in paths
    assert "items[1].price" in paths


def test_mutate_sets_nested_path():
    scanner = make_scanner()
    body = {"order": {"amount": 49.99}}
    mutated = scanner._mutate(body, "order.amount", 0.004)
    assert mutated["order"]["amount"] == 0.004
    assert body["order"]["amount"] == 49.99


def test_mutate_sets_path_inside_list():
    scanner = make_scanner()
    body = {"items": [{"price": 10.0}, {"price": 20.0}]}
    mutated = scanner._mutate(body, "items[1].price", 0.0049)
    assert mutated["items"][1]["price"] == 0.0049
    assert mutated["items"][0]["price"] == 10.0


def test_find_sibling_currency_same_object():
    scanner = make_scanner()
    body = {"order": {"amount": 100, "currency": "usd"}}
    sibling = scanner._find_sibling_currency(body, "order.amount")
    assert sibling == {"path": "order.currency", "key": "currency", "value": "usd"}


def test_find_sibling_currency_none_when_absent():
    scanner = make_scanner()
    body = {"order": {"amount": 100}}
    assert scanner._find_sibling_currency(body, "order.amount") is None


def test_extract_numeric_digs_nested_body():
    scanner = make_scanner()
    body = '{"order": {"total": 0.004, "status": "ok"}}'
    assert scanner._extract_numeric(body, "total") == pytest.approx(0.004)


def test_extract_numeric_returns_none_when_absent():
    scanner = make_scanner()
    body = '{"status": "ok"}'
    assert scanner._extract_numeric(body, "total") is None


def test_looks_ok_rejects_non_2xx():
    scanner = make_scanner()
    assert scanner._looks_ok('{"ok": true}', 403) is False


def test_looks_ok_rejects_error_body():
    scanner = make_scanner()
    assert scanner._looks_ok('{"error": "invalid request"}', 200) is False


def test_looks_ok_accepts_clean_success():
    scanner = make_scanner()
    assert scanner._looks_ok('{"status": "ok", "total": 0.004}', 200) is True
