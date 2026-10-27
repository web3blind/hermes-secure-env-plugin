"""Stock captured-CDP merchant admission and real native consent; synthetic only."""
import json

import pytest

from test_nested_code import nested as chromium_fixture
from secure_env_ingress import parent_session as ps, payment_fill as pf

nested = chromium_fixture


def page_at(nested, url, kind='page'):
    nested.pages[url] = '<iframe src="https://frame.test/pay"></iframe>'
    nested.pages['https://frame.test/pay'] = '<form onsubmit="window.submitted=true;return false"><input autocomplete="cc-name"><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><input autocomplete="cc-csc"></form>'
    nested.page.goto(url)
    nested.page.frames[-1].wait_for_selector('input')
    session = nested.context.new_cdp_session(nested.page)
    parent = session.send('Target.getTargetInfo')['targetInfo']['targetId']
    session.detach()
    assert nested.sup.focus_page(url.split('/checkout')[0])['ok']
    return parent


@pytest.mark.parametrize('scheme', ['http', 'https'])
def test_attached_exact_page_https_required(nested, scheme):
    parent = page_at(nested, scheme + '://merchant.test/checkout?private=token')
    handle = nested.capture()
    if scheme == 'http':
        with pytest.raises(ValueError):
            ps.ParentSession(handle, parent)
        with pytest.raises(ValueError):
            pf.discover(nested.sup.task_id, parent, 'https://frame.test')
    else:
        session = ps.ParentSession(handle, parent)
        try:
            assert session.origin == 'https://merchant.test'
            session.check()
        finally:
            session.drop(None)


@pytest.mark.parametrize('choice', ['once', 'deny'])
@pytest.mark.parametrize('change', [None, 'path', 'origin'])
def test_registered_consent_names_and_retains_merchant(nested, tmp_path, monkeypatch, choice, change):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress import payment_fill

    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    parent = page_at(nested, 'https://merchant.test/checkout?private=token')
    store = VaultStore(home / 'vault')
    secret = dict(card_number='4242424242424242', cardholder_name='Synthetic Holder', exp_month='12', exp_year='2031', cvc='123')
    handle = store.add_item('payment', 'Synthetic card', secret, origin='https://frame.test').id
    resolved = []
    real_backend = payment_fill.payment_backend
    def backend(*args):
        result = real_backend(*args)
        original = result.resolve_secret
        def resolve(*a):
            resolved.append(True)
            return original(*a)
        result.resolve_secret = resolve
        return result
    monkeypatch.setattr(payment_fill, 'payment_backend', backend)
    captured = nested.capture()
    def navigate():
        # Approval notifies on the protected worker: use its public CDP wire,
        # not Playwright's thread-bound greenlet.
        if change == 'path':
            captured.call('Runtime.evaluate', {'expression': 'history.replaceState({}, "", "/changed")'}, session_id=captured.page_session_id)
        elif change == 'origin':
            captured.call('Page.navigate', {'url': 'about:blank'}, session_id=captured.page_session_id)
            import time
            deadline = time.monotonic() + 5
            while captured.call('Target.getTargetInfo', {}, session_id=captured.page_session_id)['result']['targetInfo']['url'].startswith('https:'):
                assert time.monotonic() < deadline
                time.sleep(.01)
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        with payment_consent(choice, session=nested.sup.task_id, before_decision=navigate) as seen:
            raw = registry.dispatch('secure_payment_fill', dict(handle=handle, parent=parent, origin='https://frame.test'), task_id=nested.sup.task_id, session_id=nested.sup.task_id)
    result = json.loads(raw)
    expected = 'payment_declined' if choice == 'deny' else 'target_refused' if change else 'filled'
    assert result['status'] == expected, result
    prompt = json.dumps(seen)
    assert len(seen) == 1
    assert 'payment frame https://frame.test' in prompt
    assert 'merchant page https://merchant.test' in prompt
    assert 'private=token' not in prompt and '/checkout' not in prompt
    assert 'redirect.test' not in prompt
    assert secret['card_number'] not in raw + prompt
    assert bool(resolved) == (choice == 'once' and change is None)
    if change != 'origin':
        leaf = nested.page.frames[-1]
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!!e.value)') == (choice == 'once' and change is None)
        assert leaf.evaluate('!window.submitted')
