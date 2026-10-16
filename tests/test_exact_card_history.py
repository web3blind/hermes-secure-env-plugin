"""Sticky retained-identity paired with harmless geometry/decorations positives."""

import pytest
from test_nested_code import nested as chromium_fixture
from exact_card_helpers import page, registered_fill, mutate_js, navigate_js

nested = chromium_fixture

ATTACKS = {
    "identity": 'const e=document.querySelector("#cvc");e.replaceWith(e.cloneNode(true))',
    "action": 'const f=document.querySelector("form");f.action="https://wrong.test";f.action="/pay"',
    "method": 'const f=document.querySelector("form");f.method="post";f.method="get"',
    "reorder": 'const f=document.querySelector("form"),e=document.querySelector("#cvc"),n=e.nextSibling;f.prepend(e);f.insertBefore(e,n)',
    "subtree": 'const e=document.querySelector("#cvc"),p=e.parentNode,n=e.nextSibling;document.body.append(e);p.insertBefore(e,n)',
    "semantic": 'const e=document.querySelector("#cvc");e.autocomplete="one-time-code";e.removeAttribute("autocomplete")',
    "duplicate": 'const e=document.querySelector("#cvc").cloneNode(true);document.body.append(e);e.remove()',
    "id_history": 'const e=document.createElement("input");document.body.append(e);e.id="cvc";e.id="other";e.remove()',
    "base": 'const e=document.createElement("base");e.href="https://wrong.test";document.head.append(e);e.remove()',
    "label": 'const e=document.querySelector("#label");e.textContent="Password";e.textContent="Card number"',
    "readonly": 'const e=document.querySelector("#cvc");e.readOnly=true;e.readOnly=false',
    "transient_label": 'const e=document.createElement("label");e.htmlFor="pan";e.textContent="Password";document.body.append(e);e.remove()',
    "for_history": 'const e=document.createElement("label");document.body.append(e);e.htmlFor="pan";e.htmlFor="other";e.remove()',
}


@pytest.mark.parametrize("change", list(ATTACKS))
def test_consent_mutation_zero_resolve(nested, tmp_path, monkeypatch, change):
    origin, leaf, s = page(nested)
    if change == "label":
        leaf.evaluate(
            '()=>{const l=document.createElement("label");l.id="label";l.htmlFor="pan";l.textContent="Card number";document.querySelector("form").prepend(l)}'
        )
    result, seen, resolved = registered_fill(
        nested,
        tmp_path,
        monkeypatch,
        origin,
        s,
        mutation=lambda t: mutate_js(t, ATTACKS[change]),
    )
    assert result["status"] == "target_refused", result
    assert result["stage"] == "revalidation"
    assert len(seen) == 1 and not resolved
    assert leaf.evaluate("window.writes===0&&!window.clicked&&!window.submitted")


@pytest.mark.parametrize(
    "change", ["decoration", "geometry", "inline", "text", "otherform"]
)
def test_harmless_changes_accepted(nested, tmp_path, monkeypatch, change):
    origin, leaf, s = page(nested)
    scripts = {
        "decoration": 'const e=document.createElement("i");e.className="ornament";document.querySelector("form").append(e)',
        "geometry": 'document.querySelector("style").textContent+=" input{transform:scale(.8) rotate(2deg);margin:12px}"',
        "inline": 'document.querySelector("#pan").style.cssText="opacity:.7;transform:translateX(11px)";document.querySelector("form").style.margin="12px"',
        "text": 'document.querySelector(".unrelated").textContent="Updated decoration"',
        "otherform": 'const f=document.createElement("form");f.innerHTML="<input name=address>";document.body.append(f)',
    }
    result, _, _ = registered_fill(
        nested,
        tmp_path,
        monkeypatch,
        origin,
        s,
        mutation=lambda t: mutate_js(t, scripts[change]),
    )
    assert result["status"] == "filled", result
    assert leaf.evaluate("window.writes===4&&!window.clicked&&!window.submitted")


@pytest.mark.parametrize("callback", ["focus", "input"])
def test_callbacks_block_later_original_write(nested, tmp_path, monkeypatch, callback):
    origin, leaf, s = page(nested)
    leaf.evaluate(
        'kind=>document.querySelector("#pan").addEventListener(kind,()=>document.querySelector("#cvc").replaceWith(document.querySelector("#cvc").cloneNode(true)),{once:true})',
        callback,
    )
    result, _, _ = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == (
        "target_refused" if callback == "focus" else "unknown"
    ), result
    assert leaf.evaluate("window.writes") == (0 if callback == "focus" else 1)
    assert leaf.evaluate(
        'document.querySelector("#cvc").value===""&&!window.clicked&&!window.submitted'
    )


@pytest.mark.parametrize("change", ["parentnav", "providernav", "frameowner"])
def test_frame_authority_after_consent(nested, tmp_path, monkeypatch, change):
    origin, leaf, s = page(nested, topology="nested")

    def mutate(target):
        if change == "parentnav":
            navigate_js(target, "location.reload()", parent=True)
        elif change == "providernav":
            navigate_js(target, 'location.href="' + origin + '/other"')
        else:
            mutate_js(
                target,
                'const e=document.querySelector("iframe");e.replaceWith(e.cloneNode(true))',
                parent=True,
            )

    result, _, resolved = registered_fill(
        nested, tmp_path, monkeypatch, origin, s, mutation=mutate
    )
    assert result["status"] == "target_refused", result
    assert not resolved


HISTORY_ATTACKS = {
    "replace_return": 'const original=location.href;history.replaceState({},"","/other");history.replaceState({},"",original)',
    "push_same_url": 'history.pushState({},"",location.href)',
    "hash_return": 'const original=location.href;location.hash="transient";history.replaceState({},"",original)',
}


@pytest.mark.parametrize("where", ["merchant", "middle", "provider"])
@pytest.mark.parametrize("change", list(HISTORY_ATTACKS))
def test_history_approval_never_restores_authority(nested, tmp_path, monkeypatch, where, change):
    from secure_env_ingress.nested_code import _invoke

    origin, leaf, s = page(nested, topology="nested")
    expected = {"merchant": "https://parent.test", "middle": "https://middle.test", "provider": origin}[where]

    def mutate(target):
        # Invoke on the retained guard's own isolated document, including the
        # intermediate owner guard, not a newly discovered replacement target.
        retained = [(sid, guard) for sid, guard, _ in target.guards]
        retained.extend((sid, guard) for sid, _, _, guard in target.ancestry)
        for sid, guard in retained:
            if _invoke(target.supervisor, sid, guard, "function(){return location.origin}").get("value") == expected:
                _invoke(target.supervisor, sid, guard, "function(){" + HISTORY_ATTACKS[change] + ";return true}")
                return
        raise AssertionError("missing retained fixture document")

    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, s, mutation=mutate)
    assert result["status"] == "target_refused", result
    assert result["stage"] == "revalidation"
    assert len(seen) == 1 and not resolved
    assert all(f.evaluate("!window.writes&&!window.clicked&&!window.submitted") for f in nested.page.frames)


@pytest.mark.parametrize("topology", ["top", "nested"])
@pytest.mark.parametrize("callback", ["focus", "input"])
@pytest.mark.parametrize("change", ["replace_return", "push_same_url"])
def test_history_callback_stops_original_writes(nested, tmp_path, monkeypatch, topology, callback, change):
    origin, leaf, s = page(nested, topology=topology)
    leaf.evaluate('([event,script])=>document.querySelector("#pan").addEventListener(event,()=>{new Function(script)()},{once:true})', [callback, HISTORY_ATTACKS[change]])
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, s)
    assert result["status"] == ("target_refused" if callback == "focus" else "unknown"), result
    assert len(seen) == len(resolved) == 1
    assert leaf.evaluate("window.writes") == (0 if callback == "focus" else 1)
    assert leaf.evaluate('Array.from(document.querySelectorAll("#holder,#exp,#cvc")).every(e=>e.value==="")&&!window.clicked&&!window.submitted')
