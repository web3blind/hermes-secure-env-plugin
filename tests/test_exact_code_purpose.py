"""Selected credential roles must not be confused with OTP phrase context."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('markup', [
    '<input id=challenge type=password aria-label="One-time password">',
    '<input id=challenge type=password autocomplete=one-time-code>',
    '<div aria-label="Email login"><input id=challenge aria-label="Email verification code"></div>',
    '<div aria-label="Account password login"><input id=challenge autocomplete=one-time-code></div>',
])
def test_positive_otp_context(nested, markup):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(s)=>document.body.innerHTML=s', markup)
    before = leaf.evaluate('document.body.innerHTML')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(6))[0]
    try:
        assert leaf.evaluate('document.body.innerHTML') == before
        assert codes.fill(target, '123456', time.monotonic()+30)
        assert leaf.evaluate('document.querySelector("#challenge").value') == '123456'
        assert leaf.evaluate('document.body.innerHTML') == before
    finally:
        codes.release(target)


@pytest.mark.parametrize('attrs', [
    'type=password', 'name=password autocomplete=one-time-code',
    'name=email autocomplete=one-time-code', 'name=apiKey autocomplete=one-time-code',
    'autocomplete=current-password', 'autocomplete=new-password',
    'autocomplete=username', 'autocomplete=email', 'autocomplete=cc-number',
    'name=recoverySeed', 'name=secret', 'name=card',
    'aria-label="Account password" autocomplete=one-time-code',
    'aria-label="Email address" autocomplete=one-time-code',
])
def test_selected_credential_roles_refuse(nested, attrs):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(s)=>document.body.innerHTML="<input id=challenge "+s+">"', attrs)
    with pytest.raises(ValueError):
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(6))
    assert leaf.evaluate('document.querySelector("#challenge").value') == ''
