"""Registered wrong-site flows and terminal/private-session guard checks."""
import json
import threading
import time

import pytest

from test_nested_code import nested as chromium_fixture, setup_chain

from test_wrongsite_parent import authorize, wrongsite
from secure_env_ingress import code_targets as codes, payment_fill as pf

# Re-export the genuine module-scoped disposable Chromium fixture.
nested = chromium_fixture


@pytest.mark.parametrize('sites', [('parent.test', 'parent.test'), ('middle.test', 'leaf.test')])
def test_registered_nested_wrongsite(nested, tmp_path, monkeypatch, sites):
    from test_nested_code import test_registered_nested_https as run_registered
    state = {}
    def hook(home):
        state['other'], state['sid'] = wrongsite(nested)
        authorize(tmp_path, monkeypatch, nested.sup, nested.parent, home=home)
    try:
        run_registered(nested, sites, True, tmp_path, monkeypatch, wrongsite_hook=hook)
        assert nested.sup._page_session_id == state['sid']
    finally:
        if 'other' in state:
            state['other'].close()


@pytest.mark.parametrize('choice', ['once', 'deny'])
def test_registered_payment_wrongsite(nested, tmp_path, monkeypatch, choice):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    setup_chain(nested)
    nested.pages['https://parent.test/root'] = '<iframe src="https://parent.test/pay"></iframe>'
    nested.pages['https://parent.test/pay'] = '<form onsubmit="window.submitted=true;return false"><input autocomplete="cc-name"><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><input autocomplete="cc-csc"></form>'
    nested.page.reload()
    leaf = nested.page.frames[-1]
    leaf.wait_for_selector('input')
    other, previous = wrongsite(nested)
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent, home=home)
    secret = dict(card_number='4242424242424242', cardholder_name='Synthetic Holder', exp_month='12', exp_year='2031', cvc='123')
    handle = VaultStore(home / 'vault').add_item('payment', 'Synthetic card', secret, origin='https://parent.test').id
    try:
        with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
            with payment_consent(choice, session=nested.sup.task_id) as seen:
                raw = registry.dispatch('secure_payment_fill', dict(handle=handle, parent=nested.parent, origin='https://parent.test'), task_id=nested.sup.task_id, session_id=nested.sup.task_id)
        result = json.loads(raw)
        assert result['status'] == ('filled' if choice == 'once' else 'payment_declined'), result
        assert len(seen) == 1
        assert 'Synthetic card' in json.dumps(seen)
        assert secret['card_number'] not in raw + json.dumps(seen)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!!e.value)') == (choice == 'once')
        assert leaf.evaluate('!window.submitted')
        assert nested.sup._page_session_id == previous
    finally:
        other.close()


@pytest.mark.parametrize('bad', ['foreign-owner', 'invalid-target', 'other-generation', 'retired'])
@pytest.mark.parametrize('path', ['payment', 'code'])
def test_wrongsite_authority_refuses(nested, tmp_path, monkeypatch, bad, path):
    origin, leaf = setup_chain(nested)
    other, previous = wrongsite(nested)
    ledger, token = authorize(tmp_path, monkeypatch, nested.sup, nested.parent,
        owner_task='foreign-task' if bad == 'foreign-owner' else None)
    parent = nested.parent
    if bad == 'invalid-target':
        parent = 'nonexistent-synthetic-target'
    elif bad == 'other-generation':
        monkeypatch.setattr(nested.sup, 'cdp_url', nested.sup.cdp_url + '-other-generation')
    elif bad == 'retired':
        call = ledger.call(token)
        assert ledger.retire(call['owner'], call['generation'], evidence='synthetic-terminal')
    try:
        with pytest.raises(Exception):
            if path == 'code':
                codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=parent)
            else:
                pf.discover(nested.sup.task_id, parent, origin)
        assert leaf.evaluate('document.querySelector("input").value === ""')
        assert nested.sup._page_session_id == previous
    finally:
        other.close()


@pytest.mark.parametrize('change', ['navigation', 'reconnect', 'retirement'])
def test_issued_private_code_never_retargets(nested, tmp_path, monkeypatch, change):
    origin, leaf = setup_chain(nested)
    other, _ = wrongsite(nested)
    ledger, token = authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        if change == 'navigation':
            nested.page.reload()
        elif change == 'reconnect':
            nested.sup.stop()
            nested.sup.start()
        else:
            call = ledger.call(token)
            assert ledger.retire(call['owner'], call['generation'], evidence='synthetic-terminal')
        with pytest.raises(Exception):
            codes.fill(target, 'Q!7&z=R9', time.monotonic() + 20)
        if change != 'navigation':
            assert leaf.evaluate('document.querySelector("input").value === ""')
    finally:
        codes.release(target)
        assert target.lease.closed and target.lease.parent_session.closed
        other.close()


def test_private_candidate_cancel_cleanup(nested, tmp_path, monkeypatch):
    origin, _ = setup_chain(nested)
    nested.pages[origin + '/leaf'] += '<form><input autocomplete="one-time-code"></form>'
    nested.page.reload()
    nested.page.frames[-1].wait_for_selector('input')
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    selection, batch, targets = codes.CodeSelection(), threading.Event(), []
    original = codes.discover
    def observe(*args, **kwargs):
        found = original(*args, **kwargs)
        targets.extend(found)
        return found
    monkeypatch.setattr(codes, 'discover', observe)
    try:
        target, response = selection.choose('synthetic-scope', origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, batch=batch)
        assert target is None and len(response['candidates']) == 2
        selection.cancel_batch(batch)
        assert all(t.lease.closed and t.lease.parent_session.closed for t in targets)
        for t in targets:
            with pytest.raises(Exception):
                codes._call(nested.capture(), 'Target.getTargetInfo', {}, t.parent_sid)
        assert nested.sup._page_session_id == previous
    finally:
        selection.close()
        other.close()


@pytest.mark.parametrize('change', ['navigation', 'reconnect', 'retirement', 'cancel'])
def test_private_payment_terminal_guards(nested, tmp_path, monkeypatch, change):
    setup_chain(nested)
    nested.pages['https://parent.test/root'] = '<iframe src="https://parent.test/pay"></iframe>'
    nested.pages['https://parent.test/pay'] = '<form><input autocomplete="cc-name"><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><input autocomplete="cc-csc"></form>'
    nested.page.reload()
    nested.page.frames[-1].wait_for_selector('input')
    other, _ = wrongsite(nested)
    ledger, token = authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    targets = pf.discover(nested.sup.task_id, nested.parent, 'https://parent.test')
    target = targets[0]
    try:
        if change == 'navigation':
            nested.page.reload()
        elif change == 'reconnect':
            nested.sup.stop()
            nested.sup.start()
        elif change == 'retirement':
            call = ledger.call(token)
            assert ledger.retire(call['owner'], call['generation'], evidence='synthetic-terminal')
        else:
            pf.release(target)
        with pytest.raises(Exception):
            pf.assert_target(target)
    finally:
        pf.release(target)
        assert target.parent_session.closed
        with pytest.raises(Exception):
            codes._call(nested.capture(), 'Target.getTargetInfo', {}, target.parent_sid)
        other.close()


@pytest.mark.parametrize('path', ['payment', 'code'])
def test_visible_unrecorded_parent_is_not_authority(nested, tmp_path, monkeypatch, path):
    origin, _ = setup_chain(nested)
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    unknown = nested.context.new_page()
    unknown.goto('https://unrecorded.test/root')
    pc = nested.context.new_cdp_session(unknown)
    parent = pc.send('Target.getTargetInfo')['targetInfo']['targetId']
    pc.detach()
    try:
        with pytest.raises(ValueError, match='not owned'):
            if path == 'code':
                codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=parent)
            else:
                pf.discover(nested.sup.task_id, parent, origin)
        assert nested.sup._page_session_id == previous
    finally:
        unknown.close()
        other.close()


def test_concurrent_exact_private_attachments(nested, tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from secure_env_ingress.parent_session import ParentSession
    setup_chain(nested)
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            bindings = list(pool.map(lambda _: ParentSession(nested.capture(), nested.parent), range(2)))
        assert bindings[0].sid != bindings[1].sid
        bindings[0].drop(None)
        assert bindings[1].check() == bindings[1].sid
        bindings[1].drop(None)
        for binding in bindings:
            with pytest.raises(Exception):
                codes._call(nested.capture(), 'Target.getTargetInfo', {}, binding.sid)
        assert nested.sup._page_session_id == previous
    finally:
        other.close()
