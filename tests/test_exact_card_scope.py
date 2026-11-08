"""Explicit destinations are unique retained objects, not visual first matches."""

import pytest
from test_nested_code import nested as chromium_fixture
from exact_card_helpers import page, registered_fill, mutate_js

nested = chromium_fixture




def test_explicit_order_not_dom_order(nested, tmp_path, monkeypatch):
    origin, leaf, s = page(nested)
    leaf.evaluate(
        '()=>{window.order=[];document.addEventListener("input",e=>window.order.push(e.target.id));document.querySelector("form").prepend(document.querySelector("#cvc"))}'
    )
    s["fields"] = [s["fields"][3], s["fields"][2], s["fields"][1], s["fields"][0]]
    result, _, _ = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == "filled", result
    assert leaf.evaluate("window.order") == ["cvc", "exp", "holder", "pan"]




@pytest.mark.parametrize("src", ["about:blank", "https://widget.test/empty"])
def test_unrelated_frame_not_authority(nested, tmp_path, monkeypatch, src):
    origin, leaf, s = page(nested)
    leaf.evaluate(
        'src=>{const e=document.createElement("iframe");e.id="widget";e.src=src;document.body.append(e)}',
        src,
    )
    leaf.wait_for_timeout(100)
    result, _, _ = registered_fill(
        nested,
        tmp_path,
        monkeypatch,
        origin,
        s,
        mutation=lambda t: mutate_js(
            t,
            'document.querySelector("#widget").setAttribute("style","transform:scale(2)")',
        ),
    )
    assert result["status"] == "filled", result
    assert leaf.evaluate("window.writes===4&&!window.clicked&&!window.submitted")
