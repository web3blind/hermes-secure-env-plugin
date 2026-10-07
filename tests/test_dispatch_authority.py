"""Authorization races on the real native captured-CDP dispatch path."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import threading
import time
from types import SimpleNamespace

import pytest

from test_parent_transport import transport as _transport
from secure_env_ingress import bound_cdp as bc, code_targets as ct, nested_code as nc, payment_fill as pf

transport = _transport


class QueuedCapture:
    """Pause the native loop before a selected public call is enqueued."""
    def __init__(self, host, predicate):
        self.handle, self.loop = host.handle, host._loop
        self.task_id = self.handle.task_id
        self.page_session_id = self.handle.page_session_id
        self.cdp_url = self.handle.cdp_url
        self.predicate = predicate
        self.entered, self.resume = threading.Event(), threading.Event()

    def is_valid(self):
        return self.handle.is_valid()

    def call(self, method, params=None, *, session_id=None, timeout=10, before_send=None):
        if self.predicate(method, params or {}):
            def stall():
                self.entered.set()
                assert self.resume.wait(3)
            self.loop.call_soon_threadsafe(stall)
            assert self.entered.wait(1)
        return self.handle.call(method, params, session_id=session_id,
                                timeout=timeout, before_send=before_send)


@pytest.fixture
def clock(monkeypatch):
    original, offset = time.monotonic, [0]
    monkeypatch.setattr(time, 'monotonic', lambda: original() + offset[0])
    return offset


def install_results(host, wire):
    original = wire.send
    async def send(raw):
        msg = json.loads(raw)
        if msg['method'] in ('Runtime.evaluate', 'Runtime.callFunctionOn'):
            wire.commands.append(msg)
            params = msg['params']
            function = params.get('functionDeclaration', '')
            value = ([] if 'this.prepare' in function else
                     {'written': True, 'valid': True} if 'this.write' in function else
                     {'filled': 1} if msg['method'] == 'Runtime.evaluate' else True)
            host._pending_calls[msg['id']].set_result({'result': {'result': {'value': value}}})
        else:
            await original(raw)
    wire.send = send


def code_control():
    from agent.vault_login_classifier import LoginControl, ClassifiedLoginControl
    return (ClassifiedLoginControl(LoginControl.from_dict({'index': 0, 'type': 'text',
        'formIndex': 0, 'autocomplete': 'one-time-code'}), 100, 'one-time-code'),)


@contextmanager
def queued_result(gate, function, expire):
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(function)
        try:
            assert gate.entered.wait(2), 'secret command never reached the native queue'
            expire()
            gate.resume.set()
            yield future
        finally:
            gate.resume.set()


@pytest.mark.parametrize('adapter', ['top', 'nested'])
@pytest.mark.parametrize('expiry', ['authorization', 'target'])
def test_queued_code_never_outlives_authority(transport, monkeypatch, clock, adapter, expiry):
    if adapter == 'top' and expiry == 'target':
        pytest.skip('top-level target has no independent target TTL')
    host, wire, _, _ = transport
    install_results(host, wire)
    def predicate(method, params):
        return method == 'Runtime.evaluate' and 'const fills=' in params.get('expression', '') or (method == 'Runtime.callFunctionOn' and 'this.write' in params.get('functionDeclaration', ''))
    gate = QueuedCapture(host, predicate)
    now = time.monotonic()
    authorization = now + (.5 if expiry == 'authorization' else 30)
    if adapter == 'top':
        target = ct.CodeTarget('https://synthetic.test', 'Synthetic', 'synthetic', 'other',
            'nonce', 'https://synthetic.test/login', code_control(), gate)
    else:
        target = nc.NestedCodeTarget('https://synthetic.test', 'Synthetic', 'synthetic', 'other',
            'nonce', 'https://synthetic.test/login', code_control(), bc.BoundCDP(gate),
            leaf_sid='default', leaf_guard='guard', expires=now + (.5 if expiry == 'target' else 30))
        monkeypatch.setattr(nc, 'assert_target', lambda t: None)
    def fill():
        try:
            return ct.fill(target, '123456', authorization)
        except (ValueError, TimeoutError):
            return False
    with queued_result(gate, fill, lambda: clock.__setitem__(0, 1)) as future:
        assert future.result(2) is False
    assert not any(predicate(c['method'], c.get('params', {})) for c in wire.commands)


def payment_target(transport, frame='frame'):
    return pf.PaymentTarget('synthetic', 'parent', frame, 'https://synthetic.test', 0,
        (), 1, transport, 'default', 'default', 'parent-guard', frame + '-guard', time.monotonic() + 30)


def install_payment(monkeypatch):
    from tools import browser_vault_tool
    meta = SimpleNamespace(label='Synthetic card')
    backend = SimpleNamespace(get_meta=lambda h: meta,
        resolve_secret=lambda h: {'card_number': '4242424242424242', 'cvc': '123'})
    monkeypatch.setattr(pf, 'payment_backend', lambda *a: backend)
    monkeypatch.setattr(pf, 'assert_target', lambda t: None)
    monkeypatch.setattr(pf, 'mapped_fills', lambda *a: [{'index': 0, 'value': '4242424242424242', 'token': 'cc-number'}])
    monkeypatch.setattr(browser_vault_tool, '_confirm_payment_fill', lambda *a: True)
    monkeypatch.setattr(browser_vault_tool, '_bot_desktop_browser_session', lambda *a: False)


@pytest.mark.parametrize('phase', ['accepts', 'prepare', 'write'])
def test_payment_target_expiry_fences_every_secret_command(transport, monkeypatch, clock, phase):
    from dataclasses import replace
    host, wire, _, _ = transport
    install_results(host, wire)
    install_payment(monkeypatch)
    def predicate(method, params):
        return method == 'Runtime.callFunctionOn' and 'this.' + phase in params.get('functionDeclaration', '')
    gate = QueuedCapture(host, predicate)
    target = replace(payment_target(bc.BoundCDP(gate)), expires=time.monotonic() + .5)
    with queued_result(gate, lambda: pf.approved_fill(target, 'vault_test', lambda: None),
                       lambda: clock.__setitem__(0, 1)) as future:
        result = future.result(2)
    assert result['success'] is False
    assert result['status'] == ('unknown' if phase == 'write' else 'target_refused')
    assert not any(predicate(c['method'], c.get('params', {})) for c in wire.commands)


def test_selected_payment_current_cancel_is_not_sibling_lifetime(transport, monkeypatch):
    host, wire, _, _ = transport
    install_results(host, wire)
    install_payment(monkeypatch)
    old, current = threading.Event(), threading.Event()
    def predicate(method, params):
        return method == 'Runtime.callFunctionOn' and 'this.write' in params.get('functionDeclaration', '')
    gate = QueuedCapture(host, predicate)
    with bc.acquisition_scope(old):
        bound = bc.BoundCDP(gate)
    first, sibling = payment_target(bound), payment_target(bound, 'sibling')
    monkeypatch.setattr(pf, 'discover', lambda *a: [first, sibling])
    released = []
    monkeypatch.setattr(pf, 'release', released.append)
    picker = pf.PaymentSelection()
    args = ('scope', 'synthetic', 'parent', first.origin, 'vault_test')
    try:
        _, response = picker.choose(*args, batch=old)
        token, sibling_token = [c['selection'] for c in response['candidates']]
        selected, _ = picker.choose(*args, selection=token, batch=current)
        # The registered tool's current operation scope must be carried to dispatch.
        scope = getattr(bc, 'operation_scope', lambda **kw: bc.acquisition_scope(kw['cancelled']))
        def work():
            with scope(cancelled=current):
                return pf.approved_fill(selected, 'vault_test', lambda: None)
        with queued_result(gate, work, lambda: picker.cancel_batch(current)) as future:
            result = future.result(2)
        assert not result['success'] and result['status'] == 'unknown'
        assert not any(predicate(c['method'], c.get('params', {})) for c in wire.commands)
        assert not old.is_set() and not released
        assert picker.choose(*args, selection=sibling_token, batch=threading.Event())[0] is sibling
        assert bound.valid()
    finally:
        picker.close()


@pytest.mark.parametrize('message', [
    'CDP error on id=1: No frame for given id found; synthetic-sensitive-tail',
    'CDP error on id=1: unrelated synthetic-sensitive-tail',
])
def test_frame_error_is_typed_and_secret_free(transport, message):
    host, wire, _, _ = transport
    async def send(raw):
        msg = json.loads(raw)
        wire.commands.append(msg)
        host._pending_calls[msg['id']].set_exception(RuntimeError(message))
    wire.send = send
    with pytest.raises(ValueError) as caught:
        bc.BoundCDP(host.handle).call('Page.createIsolatedWorld', {'frameId': 'exact'}, 'default')
    expected = getattr(bc, 'FrameUnavailable', None)
    assert expected is not None
    assert isinstance(caught.value, expected) is ('No frame for given id found' in message)
    assert 'synthetic-sensitive-tail' not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


@pytest.mark.parametrize('adapter', ['nested', 'payment'])
def test_native_oopif_error_attaches_only_exact_frame(transport, monkeypatch, adapter):
    host, wire, _, sessions = transport
    original = wire.send
    async def send(raw):
        msg = json.loads(raw)
        if msg['method'] == 'Page.createIsolatedWorld':
            wire.commands.append(msg)
            future = host._pending_calls[msg['id']]
            if msg.get('sessionId') == 'default':
                future.set_exception(RuntimeError('CDP error: No frame for given id found; synthetic-sensitive-tail'))
            else:
                future.set_result({'result': {'executionContextId': 7}})
        else:
            await original(raw)
    wire.send = send
    bound = bc.BoundCDP(host.handle)
    if adapter == 'nested':
        lease = nc._Lease(bound)
        try:
            sid, context = nc._context(bound, 'default', 'exact-child', lease)
            assert context == 7 and sessions[sid] == 'exact-child'
        finally:
            lease.close()
    else:
        class Parent:
            transport, sid = bound, 'default'
            def drop(self, obj):
                pass
        from secure_env_ingress import parent_session
        monkeypatch.setattr(parent_session, 'ParentSession', lambda *a: Parent())
        monkeypatch.setattr(pf, '_supervisor', lambda task: host.handle)
        original_call = pf._call
        def setup(sup, method, params=None, sid=None):
            data = {'Page.getFrameTree': {'frameTree': {'frame': {'id': 'root'}}},
                'DOM.getDocument': {'root': {'nodeId': 1}},
                'DOM.querySelectorAll': {'nodeIds': [2]},
                'DOM.describeNode': {'node': {'frameId': 'exact-child', 'backendNodeId': 3}}}
            if method in data:
                return {'result': data[method]}
            # Mismatched origin exercises attach and exact cleanup without a form.
            if method == 'Runtime.evaluate':
                return {'result': {'result': {'value': 'https://other.test'}}}
            return original_call(sup, method, params, sid)
        monkeypatch.setattr(pf, '_call', setup)
        assert pf.discover('synthetic', 'parent', 'https://synthetic.test') == []
    attaches = [c['params']['targetId'] for c in wire.commands if c['method'] == 'Target.attachToTarget']
    assert attaches == ['exact-child']
    assert set(sessions) == {'default', 'sibling'}
