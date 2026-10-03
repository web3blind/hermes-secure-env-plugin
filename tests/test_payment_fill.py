"""Protected payment adapter, synthetic values and disposable native Vault only."""
import json
from types import SimpleNamespace

import pytest

from generic_helpers import registered
from test_runtime_e2e import make_runtime
from payment_consent_helpers import payment_consent


def test_additive_registered_payment_tool(tmp_path, monkeypatch):
    from tools.registry import registry
    from gateway.run import _profile_runtime_scope
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        entry = registry.get_entry('secure_payment_fill', scope=str(home))
        assert entry is not None
        assert set(entry.schema['parameters']['required']) == {'handle', 'parent', 'origin'}
        assert not {'selector', 'code', 'endpoint', 'card_number'} & set(entry.schema['parameters']['properties'])
        assert 'confirmation' in entry.schema['description']
        from secure_env_ingress import payment_fill as pf
        monkeypatch.setattr(pf, 'payment_backend', lambda *a: pytest.fail('invalid flag must refuse before backend'))
        with payment_consent('missing', session='task') as seen:
            for invalid in ('true', 1, None, []):
                result = json.loads(registry.dispatch('secure_payment_fill',
                    dict(handle='vault_fixture', parent='p', origin='https://frame.test', resume_existing=invalid), task_id='task'))
                assert result == {'success': False, 'status': 'session_binding'}
            assert not seen
        assert entry.schema['parameters']['properties']['resume_existing']['type'] == 'boolean'
        assert entry.schema['parameters']['properties']['resume_existing']['default'] is False


def controls(tokens):
    from agent.vault_login_classifier import LoginControl, ClassifiedLoginControl
    return tuple(ClassifiedLoginControl(LoginControl.from_dict({'index': i, 'autocomplete': t,
        'type': 'text', 'formIndex': 0}), 100, t) for i, t in enumerate(tokens))


@pytest.mark.parametrize('tokens,expected', [
    (['cc-number', 'cc-exp-month', 'cc-exp-year', 'cc-csc'], ['4242424242424242', '12', '2031', '123']),
    (['cc-number', 'cc-exp', 'cc-csc'], ['4242424242424242', '12/31', '123']),
])
def test_exact_expiry_mapping(tokens, expected):
    from secure_env_ingress.payment_fill import mapped_fills
    secret = dict(card_number='4242424242424242', exp_month='12', exp_year='2031', cvc='123')
    assert [x['value'] for x in mapped_fills(controls(tokens), secret)] == expected


@pytest.mark.parametrize('tokens', [
    ['cc-number', 'cc-number', 'cc-exp', 'cc-csc'], ['cc-number', 'cc-exp'],
    ['cc-number', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc'],
])
def test_ambiguous_or_incomplete_group_refuses(tokens):
    from secure_env_ingress.payment_fill import validate_group
    with pytest.raises(ValueError):
        validate_group(controls(tokens))


@pytest.mark.parametrize('choice', ['deny', 'unresolved', 'missing'])
def test_real_consent_refusal_never_resolves(choice, monkeypatch):
    from secure_env_ingress import payment_fill as pf
    backend = SimpleNamespace(needs_unlock=False, name='local',
        get_meta=lambda h: SimpleNamespace(kind='payment', origin='https://frame.test', label='Synthetic card'))
    backend.resolve_secret = lambda h: pytest.fail('declined consent must not resolve secret')
    monkeypatch.setattr(pf, 'payment_backend', lambda *a: backend)
    monkeypatch.setattr(pf, 'assert_target', lambda *a: None)
    target = SimpleNamespace(origin='https://frame.test', expires=1e30)
    with payment_consent(choice) as seen:
        result = pf.approved_fill(target, 'vault_fixture', lambda: None)
    assert result['status'] == 'payment_declined'
    assert len(seen) == (0 if choice == 'missing' else 1)


def test_consumed_scoped_expiring_choices(monkeypatch):
    from secure_env_ingress import payment_fill as pf
    target = SimpleNamespace(origin='https://frame.test', parent='p', frame='f', form_index=0, expires=1e30)
    monkeypatch.setattr(pf, 'discover', lambda *a: [target, target])
    monkeypatch.setattr(pf, 'assert_target', lambda *a: None)
    monkeypatch.setattr(pf, 'release', lambda *a: None)
    selections = pf.PaymentSelection()
    args = ('scope', 'task', 'p', 'https://frame.test', 'vault_fixture')
    _, response = selections.choose(*args)
    token = response['candidates'][0]['selection']
    assert set(response['candidates'][0]) == {'selection', 'parent', 'frame', 'origin', 'form_index'}
    with pytest.raises(ValueError):
        selections.choose('other', *args[1:], selection=token)
    assert selections.choose(*args, selection=token)[0] is target
    with pytest.raises(ValueError):
        selections.choose(*args, selection=token)
    token = response['candidates'][1]['selection']
    monkeypatch.setattr(pf.time, 'monotonic', lambda: 1e31)
    with pytest.raises(ValueError):
        selections.choose(*args, selection=token)


def test_registered_wrong_context_refuses(tmp_path, monkeypatch):
    from tools.registry import registry
    from gateway.run import _profile_runtime_scope
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        result = json.loads(registry.dispatch('secure_payment_fill',
            {'handle': 'vault_fixture', 'parent': 'p', 'origin': 'https://frame.test'}, task_id='task'))
    assert result == {'success': False, 'status': 'session_binding'}


@pytest.mark.parametrize('changed', ['task', 'parent', 'origin', 'handle'])
def test_selection_binding_cannot_retarget(changed, monkeypatch):
    from secure_env_ingress import payment_fill as pf
    target = SimpleNamespace(origin='https://frame.test', parent='p', frame='f', form_index=0, expires=1e30)
    monkeypatch.setattr(pf, 'discover', lambda *a: [target, target])
    monkeypatch.setattr(pf, 'assert_target', lambda *a: None)
    monkeypatch.setattr(pf, 'release', lambda *a: None)
    selections = pf.PaymentSelection()
    args = ['scope', 'task', 'p', 'https://frame.test', 'vault_fixture']
    _, response = selections.choose(*args)
    token = response['candidates'][0]['selection']
    altered = args.copy()
    altered[{'task': 1, 'parent': 2, 'origin': 3, 'handle': 4}[changed]] = 'other'
    with pytest.raises(ValueError):
        selections.choose(*altered, selection=token)
    assert selections.choose(*args, selection=token)[0] is target
    selections.close()


@pytest.mark.parametrize('failure', ['scope', 'metadata', 'target'])
def test_approval_revalidation_precedes_resolution(failure, monkeypatch):
    from secure_env_ingress import payment_fill as pf
    meta = SimpleNamespace(kind='payment', origin='https://frame.test', label='Synthetic card')
    state = {'approved': False}
    backend = SimpleNamespace(get_meta=lambda h: meta,
        resolve_secret=lambda h: pytest.fail('changed binding must not resolve a secret'))
    monkeypatch.setattr(pf, 'payment_backend', lambda *a: backend)
    def check_target(t):
        if failure == 'target' and state['approved']:
            raise ValueError('changed document')
    def check_scope():
        if failure == 'scope' and state['approved']:
            raise ValueError('changed scope')
    monkeypatch.setattr(pf, 'assert_target', check_target)
    def change():
        state['approved'] = True
        if failure == 'metadata':
            backend.get_meta = lambda h: SimpleNamespace(kind='payment', origin=meta.origin, label='Other label')
    with payment_consent('once', before_decision=change):
        result = pf.approved_fill(SimpleNamespace(origin=meta.origin), 'vault_fixture', check_scope)
    assert result == {'success': False, 'status': 'target_refused', 'stage': 'revalidation'}


@pytest.mark.parametrize('handle,origin', [('op:fixture', 'https://frame.test'), ('vault_fixture', 'http://frame.test'),
    ('vault_fixture', 'https://frame.test/path'), ('vault_fixture', 'https://frame.test:443')])
def test_invalid_handle_or_nonexact_origin_refuses(handle, origin):
    from secure_env_ingress.payment_fill import payment_backend
    with pytest.raises(ValueError):
        payment_backend(handle, origin)


@pytest.mark.parametrize('changed', ['task', 'profile', 'cron', 'owner', 'platform'])
def test_registered_scope_refuses_before_browser(changed, tmp_path, monkeypatch):
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress import payment_fill as pf
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr(pf, 'payment_backend', lambda *a: pytest.fail('scope failure before backend/browser'))
    values = dict(platform='telegram', user_id='7', chat_id='7', chat_type='dm',
        session_id='task', session_key='key', profile='', cron_session='')
    key = {'profile': 'profile', 'cron': 'cron_session', 'owner': 'user_id', 'platform': 'platform', 'task': 'session_id'}[changed]
    values[key] = 'other'
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        tokens = sc.set_session_vars(**values)
        try:
            result = json.loads(registry.dispatch('secure_payment_fill',
                {'handle': 'vault_fixture', 'parent': 'p', 'origin': 'https://frame.test'}, task_id='task'))
        finally:
            sc.clear_session_vars(tokens)
    assert result == {'success': False, 'status': 'session_binding'}


@pytest.mark.asyncio
async def test_cancel_during_real_consent_stops_worker_before_resolution(tmp_path, monkeypatch):
    import asyncio
    import threading
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress import payment_fill as pf
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    target = SimpleNamespace(origin='https://frame.test')
    backend = SimpleNamespace(get_meta=lambda h: SimpleNamespace(label='Synthetic card'),
        resolve_secret=lambda h: pytest.fail('cancelled consent must not resolve'))
    released = []
    monkeypatch.setattr(pf, 'payment_backend', lambda *a: backend)
    monkeypatch.setattr(pf, 'assert_target', lambda *a: None)
    monkeypatch.setattr(pf.PaymentSelection, 'choose', lambda *a, **kw: (target, None))
    monkeypatch.setattr(pf, 'release', released.append)
    ready, proceed = threading.Event(), threading.Event()
    def before():
        ready.set()
        assert proceed.wait(5)
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        with payment_consent('once', session='task', before_decision=before) as seen:
            handler = registry.get_entry('secure_payment_fill', scope=str(home)).handler
            worker = asyncio.create_task(handler(dict(handle='vault_fixture', parent='p', origin=target.origin), task_id='task'))
            assert await asyncio.to_thread(ready.wait, 5)
            worker.cancel()
            await asyncio.sleep(0)
            proceed.set()
            with pytest.raises(asyncio.CancelledError):
                await worker
    assert released == [target] and len(seen) == 1
