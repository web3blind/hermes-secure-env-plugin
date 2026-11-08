"""Synthetic hidden service-frame regressions, without live accounts."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


def code_spec():
    return {
        'version': 1, 'purpose': 'transient_code', 'layout': 'ordered_cells',
        'fields': [{'selector': f'input[name="code{i}"]'} for i in range(6)],
        'validation': {'charset': 'ascii_digits', 'exact_length': 6, 'multiline': False},
    }


def setup_cells(nested, blank=False):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('''async blank => {
        document.body.innerHTML='';
        for (let i=0;i<6;i++) {
            const e=document.createElement('input');
            e.name='code'+i;e.autocomplete='one-time-code';document.body.append(e);
        }
        const frame=document.createElement('iframe');
        frame.style.visibility='hidden';
        if(blank)frame.src='about:blank';else frame.srcdoc='<div id=service>Service frame</div>';
        await new Promise(resolve=>{frame.onload=resolve;document.body.append(frame)});
    }''', blank)
    return origin, leaf


def discover(nested, origin):
    return codes.discover(origin, 'Synthetic hidden sibling', nested.sup.task_id,
                          parent=nested.parent, target_spec=code_spec())[0]


@pytest.mark.parametrize('blank', [False, True])
def test_hidden_zero_match_sibling_does_not_block_visible_code(nested, blank):
    origin, leaf = setup_cells(nested, blank)
    target = discover(nested, origin)
    try:
        assert codes.fill(target, '123456', time.monotonic()+30)
        assert leaf.evaluate("[...document.querySelectorAll('input')].map(e=>e.value).join('')") == '123456'
    finally:
        codes.release(target)






def test_legacy_hint_with_hidden_empty_sibling(nested):
    origin, leaf = setup_cells(nested)
    leaf.evaluate('''()=>{
        document.querySelectorAll('input').forEach(e=>e.remove());
        const e=document.createElement('input');e.id='challenge';
        e.autocomplete='one-time-code';e.maxLength=6;document.body.prepend(e);
    }''')
    target = codes.discover(origin, 'Synthetic legacy sibling', nested.sup.task_id,
                           parent=nested.parent, field_selector='#challenge')[0]
    try:
        assert codes.fill(target, '123456', time.monotonic()+30)
        assert leaf.evaluate("document.querySelector('#challenge').value") == '123456'
    finally:
        codes.release(target)
