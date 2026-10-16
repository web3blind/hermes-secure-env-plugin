"""Generic token boundaries, including unchanged observed public ancestor classes."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_indexed_code_browser import markup
from secure_env_ingress import code_targets as codes
from secure_env_ingress.grouped_otp import GROUP_JS


@pytest.mark.parametrize('selector', [None, 'input[name="code-0"]'])
@pytest.mark.parametrize('ancestor', [
    'PasswordlessCodeContainer-sc-6187bfee-0 hOxTXQ', 'PasswordlessLogin',
])
def test_passwordless_ancestor(nested, selector, ancestor):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', markup())
    leaf.evaluate('(name)=>document.querySelector("section").className=name', ancestor)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, field_selector=selector)[0]
    try:
        assert codes.fill(target, '123456', time.monotonic()+60)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value).join("")==="123456"')
        assert leaf.evaluate('document.querySelector("section").className') == ancestor
    finally:
        codes.release(target)


@pytest.mark.parametrize('selector', [None, 'input[name="code-0"]'])
def test_credential_conflicts_still_refuse(nested, selector):
    origin, leaf = setup_chain(nested)
    for ancestor in ['APIkey', 'APIkeyInput', 'apiKey', 'APIKey', 'APIKeyInput',
                     'APIPasswordInput', 'password', 'PasswordInput', 'password-foo',
                     'privateKey', 'CardInput', 'credit-card',
                     'PaymentContainer', 'billing', 'recovery', 'seed', 'userName']:
        leaf.evaluate('(html)=>document.body.innerHTML=html', markup())
        leaf.evaluate('(name)=>document.querySelector("section").className=name', ancestor)
        assert leaf.eval_on_selector('input', GROUP_JS)['forbidden'], ancestor
        try:
            targets = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                                     parent=nested.parent, field_selector=selector)
        except ValueError:
            targets = []
        assert targets == [], ancestor
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
    for attrs in [{'type':'password'}, {'type':'email'}, {'autocomplete':'current-password'},
                  {'autocomplete':'cc-number'}, {'autocomplete':'cc-csc'}]:
        leaf.evaluate('(html)=>document.body.innerHTML=html', markup())
        leaf.evaluate('(attrs)=>{for(const [k,v] of Object.entries(attrs))document.querySelector("input").setAttribute(k,v)}', attrs)
        try:
            targets = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                                     parent=nested.parent, field_selector=selector)
        except ValueError:
            targets = []
        assert targets == [], attrs
