"""Plain editing hosts: exact text reflection, no markup adoption or guessing."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes
from exact_card_helpers import page, registered_fill, mutate_js


@pytest.mark.parametrize('editing', ['true', 'plaintext-only'])
@pytest.mark.parametrize('event', ['before', 'input'])
def test_code_editor_br_history_refuses(nested, editing, event):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(v)=>document.body.innerHTML=`<div id=challenge contenteditable="${v}"></div>`', editing)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(3, multiline=True))[0]
    attack = 'const e=document.querySelector("#challenge"),b=document.createElement("br");e.append(b);b.remove()'
    if event == 'before':
        leaf.evaluate(attack)
    else:
        leaf.evaluate('(s)=>document.querySelector("#challenge").addEventListener("input",()=>{'+attack+'},{once:true})', '')
    try:
        try:
            assert not codes.fill(target, 'A\nB', time.monotonic()+120)
        except ValueError:
            pass
        assert leaf.evaluate('document.querySelector("#challenge").children.length===0')
        if event == 'before':
            assert leaf.evaluate('document.querySelector("#challenge").textContent===""')
    finally:
        codes.release(target)


@pytest.mark.parametrize('event', ['consent', 'input'])
def test_card_editor_br_history_blocks_later_fields(nested, tmp_path, monkeypatch, event):
    origin, leaf, target_spec = page(nested, kind='editable')
    attack = 'const e=document.querySelector("#cvc"),b=document.createElement("br");e.append(b);b.remove()'
    mutation = None
    if event == 'consent':
        def mutation(t):
            mutate_js(t, attack)
    else:
        leaf.evaluate('()=>document.querySelector("#pan").addEventListener("input",()=>{'+attack+'},{once:true})')
    result, _, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target_spec, mutation=mutation)
    assert result['status'] == ('target_refused' if event == 'consent' else 'unknown'), result
    assert not resolved if event == 'consent' else len(resolved) == 1
    assert leaf.evaluate('document.querySelector("#cvc").textContent===""&&!window.clicked&&!window.submitted')


@pytest.mark.parametrize('markup', ['<b>rich</b>', '<br>', '<!--comment-->'])
def test_card_rich_editor_before_consent_refuses(nested, tmp_path, monkeypatch, markup):
    origin, leaf, target_spec = page(nested, kind='editable')
    leaf.evaluate('(s)=>document.querySelector("#pan").innerHTML=s', markup)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target_spec)
    assert result['status'] == 'target_refused'
    assert not seen and not resolved
    assert leaf.evaluate('window.writes===0&&!window.clicked&&!window.submitted')


def test_retained_document_release_never_calls_native_close(nested):
    from secure_env_ingress.nested_code import _invoke
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<input id=challenge>"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())[0]
    key = (target.leaf_sid, target.lease.contexts[target.leaf_guard])
    doc = target.lease.census_documents[key]
    _invoke(target.supervisor, target.leaf_sid, doc,
            'function(){this.close=()=>this.body.setAttribute("data-close-called","yes")}')
    codes.release(target)
    assert leaf.evaluate('!document.body.hasAttribute("data-close-called")')
    assert target.lease.closed and not target.lease.objects

