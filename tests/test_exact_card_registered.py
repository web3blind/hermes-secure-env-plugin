"""Actual registered handler -> native owned approval -> original synthetic CDP."""

import json
import pytest
from test_nested_code import nested as chromium_fixture
from exact_card_helpers import page, registered_fill

nested = chromium_fixture


@pytest.mark.parametrize(
    "topology,kind",
    [
        ("top", "input"),
        ("top", "textarea"),
        ("top", "plaintext"),
        ("top", "editable"),
        ("nested", "editable"),
        ("shadow", "editable"),
        ("closed", "editable"),
        ("same", "input"),
        ("nested", "input"),
        ("shadow", "input"),
        ("closed", "input"),
        ("multi", "input"),
    ],
)
def test_registered_exact_card(nested, tmp_path, monkeypatch, topology, kind):
    origin, leaf, s = page(nested, topology=topology, kind=kind)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == "filled", result
    assert result["filled_fields"] == 4
    assert len(seen) == len(resolved) == 1
    assert s["merchant_origin"] in json.dumps(seen) and origin in json.dumps(seen)
    assert leaf.evaluate("!window.clicked&&!window.submitted")
    count = sum(f.evaluate("window.writes||0") for f in nested.page.frames)
    assert count == 4


@pytest.mark.parametrize("choice", ["deny", "unresolved", "missing"])
def test_native_decline_before_resolve(nested, tmp_path, monkeypatch, choice):
    origin, leaf, s = page(nested)
    result, seen, resolved = registered_fill(
        nested, tmp_path, monkeypatch, origin, s, choice=choice
    )
    assert result["status"] == "payment_declined", result
    assert not resolved
    assert leaf.evaluate("window.writes===0&&!window.clicked&&!window.submitted")


@pytest.mark.parametrize("fmt", ["digits", "space4", "hyphen4"])
def test_registered_pan_fixed_format(nested, tmp_path, monkeypatch, fmt):
    origin, leaf, s = page(nested)
    s["fields"][0]["format"] = fmt
    result, _, _ = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == "filled", result
    assert leaf.evaluate(
        'document.querySelector("#pan").value.replace(/[ -]/g,"").length===16'
    )


@pytest.mark.parametrize("layout", ["split", "monthyear"])
def test_registered_explicit_layouts(nested, tmp_path, monkeypatch, layout):
    origin, leaf, s = page(
        nested,
        split=[4, 4, 4, 4] if layout == "split" else None,
        monthyear=layout == "monthyear",
    )
    result, _, _ = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == "filled", result
    assert leaf.evaluate("!window.clicked&&!window.submitted")


@pytest.mark.parametrize("change", ["merchant", "provider", "vault", "lf"])
def test_binding_and_linebreak_before_write(nested, tmp_path, monkeypatch, change):
    origin, leaf, s = page(nested)
    secret = None
    vault_origin = None
    if change == "merchant":
        s["merchant_origin"] = "https://wrong.test"
    elif change == "provider":
        origin = "https://wrong.test"
    elif change == "vault":
        vault_origin = "https://wrong.test"
    else:
        from exact_card_helpers import SECRET

        secret = dict(SECRET, cardholder_name="Fake\nHolder")
    result, seen, resolved = registered_fill(
        nested,
        tmp_path,
        monkeypatch,
        origin,
        s,
        secret=secret,
        vault_origin=vault_origin,
    )
    assert result["status"] == "target_refused", result
    assert leaf.evaluate("window.writes===0")
    if change != "lf":
        assert not seen and not resolved
