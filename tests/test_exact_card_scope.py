"""Explicit destinations are unique retained objects, not visual first matches."""

import pytest
from test_nested_code import nested as chromium_fixture
from exact_card_helpers import page, registered_fill, mutate_js

nested = chromium_fixture


@pytest.mark.parametrize(
    "change",
    [
        "hidden_duplicate",
        "conflict",
        "name_conflict",
        "plaintext_action",
        "cross_action",
        "other_form",
        "new_root",
        "new_label",
    ],
)
def test_scope_refusals(nested, tmp_path, monkeypatch, change):
    origin, leaf, s = page(
        nested, kind="plaintext" if change == "plaintext_action" else "input"
    )
    scripts = {
        "hidden_duplicate": 'const e=document.querySelector("#pan").cloneNode(true);e.type="hidden";document.body.append(e)',
        "conflict": 'document.querySelector("#pan").autocomplete="current-password"',
        "name_conflict": 'document.querySelector("#pan").name="password"',
        "plaintext_action": 'document.querySelector("form").action="https://wrong.test"',
        "cross_action": 'document.querySelector("form").action="https://wrong.test"',
        "other_form": 'const f=document.createElement("form");document.body.append(f);f.append(document.querySelector("#cvc"))',
        "new_root": 'const h=document.createElement("aside");document.body.append(h);h.attachShadow({mode:"closed"}).innerHTML="<input id=pan>"',
        "new_label": 'const l=document.createElement("label");l.htmlFor="pan";l.textContent="Password";document.body.append(l)',
    }
    after = change in ("new_root", "new_label")
    if not after:
        leaf.evaluate("()=>{" + scripts[change] + "}")
    result, seen, resolved = registered_fill(
        nested,
        tmp_path,
        monkeypatch,
        origin,
        s,
        mutation=(lambda t: mutate_js(t, scripts[change])) if after else None,
    )
    assert result["status"] == "target_refused", result
    assert not resolved
    assert bool(seen) == after
    assert leaf.evaluate("window.writes===0&&!window.clicked&&!window.submitted")


def test_explicit_order_not_dom_order(nested, tmp_path, monkeypatch):
    origin, leaf, s = page(nested)
    leaf.evaluate(
        '()=>{window.order=[];document.addEventListener("input",e=>window.order.push(e.target.id));document.querySelector("form").prepend(document.querySelector("#cvc"))}'
    )
    s["fields"] = [s["fields"][3], s["fields"][2], s["fields"][1], s["fields"][0]]
    result, _, _ = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == "filled", result
    assert leaf.evaluate("window.order") == ["cvc", "exp", "holder", "pan"]


def test_nonmutating_discovery(nested, monkeypatch):
    from secure_env_ingress import exact_card as ec

    origin, leaf, s = page(nested)
    before = leaf.evaluate(
        'Array.from(document.querySelectorAll("*"),e=>Array.from(e.attributes,a=>[a.name,a.value]))'
    )
    t = ec.discover(nested.sup.task_id, nested.parent, origin, s)[0]
    try:
        after = leaf.evaluate(
            'Array.from(document.querySelectorAll("*"),e=>Array.from(e.attributes,a=>[a.name,a.value]))'
        )
        assert after == before
        assert leaf.evaluate("window.writes===0")
    finally:
        ec.release(t)


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
