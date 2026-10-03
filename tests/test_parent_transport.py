"""Deterministic supervisor-loop races; fake wires, never live endpoints."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from types import SimpleNamespace

import pytest

from secure_env_ingress import parent_session as ps
from secure_env_ingress.code_targets import _call
from tools.browser_supervisor import CDPSupervisor


@pytest.fixture
def transport(monkeypatch, tmp_path):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    sup = SimpleNamespace(task_id='synthetic', _loop=loop, cdp_url='ws://isolated/devtools/browser/generation',
        _active=True, _page_session_id='default', _next_call_id=1, _pending_calls={})
    sup._cdp = lambda *a, **kw: CDPSupervisor._cdp(sup, *a, **kw)
    sessions = {'default': 'other', 'sibling': 'parent'}
    class Wire:
        def __init__(self):
            self.commands = []
            self.delay = 0

            self.switch_on_send = False
        async def send(self, raw):
            msg = json.loads(raw)
            if msg['method'] == 'Target.detachFromTarget' and getattr(self, 'detach_delay', 0):
                await asyncio.sleep(self.detach_delay)
            self.commands.append(msg)
            if self.switch_on_send:
                sup._ws = replacement
                await asyncio.sleep(0)
            method, params = msg['method'], msg.get('params', {})
            if method == 'Target.attachToTarget':
                sid = 'private-' + str(msg['id'])
                sessions[sid] = params['targetId']
                result = {'sessionId': sid}
            elif method == 'Target.detachFromTarget':
                sessions.pop(params['sessionId'], None)
                result = {}
            elif method == 'Target.getTargetInfo':
                target = sessions.get(msg.get('sessionId')) if msg.get('sessionId') else params['targetId']
                if target is None:
                    raise ValueError('detached')
                result = {'targetInfo': {'targetId': target, 'type': 'page', 'url': 'https://synthetic.test'}}
            else:
                result = {}
            def reply():
                fut = sup._pending_calls.get(msg['id'])
                if fut is not None and not fut.done():
                    fut.set_result({'result': result})
            loop.call_later(self.delay if method == 'Target.attachToTarget' else 0, reply)
    wire, replacement = Wire(), Wire()
    sup._ws = wire
    monkeypatch.setattr(ps, '_supervisor', lambda _: sup)
    monkeypatch.setattr(ps, '_proof', lambda *a: ('owner', 'generation', 'call'))
    yield sup, wire, replacement, sessions
    async def stop():
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    asyncio.run_coroutine_threadsafe(stop(), loop).result(2)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(2)
    loop.close()


def test_reconnect_between_check_and_dispatch(transport, monkeypatch):
    sup, wire, replacement, sessions = transport
    parent = ps.ParentSession(sup, 'parent')
    entered, resume = threading.Event(), threading.Event()
    def stall():
        entered.set()
        resume.wait(2)
    sup._loop.call_soon_threadsafe(stall)
    assert entered.wait(1)
    try:
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(_call, getattr(parent, 'transport', sup), 'Runtime.evaluate', {'expression': 'synthetic'}, parent.sid)
            time.sleep(.03)
            sup._ws = replacement
            resume.set()
            with pytest.raises(ValueError, match='connection'):
                future.result(2)
        assert not replacement.commands
    finally:
        resume.set()
        parent.drop(None)
    assert set(sessions) == {'default', 'sibling'}


def test_reconnect_during_send_rejects_result(transport):
    sup, wire, replacement, _ = transport
    parent = ps.ParentSession(sup, 'parent')
    wire.switch_on_send = True
    try:
        with pytest.raises(ValueError, match='connection'):
            _call(getattr(parent, 'transport', sup), 'Runtime.evaluate', {'expression': 'synthetic'}, parent.sid)
        assert not replacement.commands
    finally:
        wire.switch_on_send = False
        parent.drop(None)


@pytest.mark.parametrize('delay', [.08, .16])
def test_timed_out_attach_has_late_cleanup_owner(transport, monkeypatch, delay):
    from tools import browser_supervisor as host
    sup, wire, _, sessions = transport
    wire.delay = delay
    original = host._schedule
    monkeypatch.setattr(host, '_schedule', lambda coro, loop, timeout=6: original(coro, loop, timeout=.03))
    try:
        from secure_env_ingress import bound_cdp
    except ImportError:
        pass
    else:
        monkeypatch.setattr(bound_cdp, 'CALL_TIMEOUT', .03)
        monkeypatch.setattr(bound_cdp, 'REPLY_TIMEOUT', .04)
    with pytest.raises(TimeoutError):
        ps.ParentSession(sup, 'parent')
    time.sleep(delay + .1)
    assert set(sessions) == {'default', 'sibling'}
    assert not sup._pending_calls


def test_queued_attach_timeout_sends_no_late_command(transport, monkeypatch):
    from secure_env_ingress import bound_cdp
    sup, wire, _, sessions = transport
    entered, resume = threading.Event(), threading.Event()
    original = ps._call
    def observe(transport, method, params=None, sid=None):
        result = original(transport, method, params, sid)
        if method == 'Target.getTargetInfo' and params and params.get('targetId') == 'parent':
            def stall():
                entered.set()
                resume.wait(1)
            sup._loop.call_soon_threadsafe(stall)
            assert entered.wait(1)
        return result
    monkeypatch.setattr(ps, '_call', observe)
    monkeypatch.setattr(bound_cdp, 'CALL_TIMEOUT', .03)
    try:
        with pytest.raises(TimeoutError):
            ps.ParentSession(sup, 'parent')
    finally:
        resume.set()
    time.sleep(.1)
    assert not any(c['method'] == 'Target.attachToTarget' for c in wire.commands)
    assert set(sessions) == {'default', 'sibling'}


def test_reconnect_after_lookup_before_attach(transport, monkeypatch):
    sup, wire, replacement, sessions = transport
    original = ps._call
    def observe(transport, method, params=None, sid=None):
        result = original(transport, method, params, sid)
        if method == 'Target.getTargetInfo' and params and params.get('targetId') == 'parent':
            sup._ws = replacement
        return result
    monkeypatch.setattr(ps, '_call', observe)
    with pytest.raises(ValueError, match='connection'):
        ps.ParentSession(sup, 'parent')
    assert not replacement.commands
    assert set(sessions) == {'default', 'sibling'}


def test_cancel_during_attach_retains_exact_cleanup(transport):
    from secure_env_ingress.bound_cdp import acquisition_scope
    sup, wire, _, sessions = transport
    wire.delay = .1
    batch = threading.Event()
    def construct():
        with acquisition_scope(batch):
            return ps.ParentSession(sup, 'parent')
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(construct)
        deadline = time.monotonic() + 1
        while not any(c['method'] == 'Target.attachToTarget' for c in wire.commands):
            assert time.monotonic() < deadline
            time.sleep(.005)
        batch.set()
        with pytest.raises(ValueError, match='cancelled'):
            future.result(1)
    deadline = time.monotonic() + 1
    while set(sessions) != {'default', 'sibling'}:
        assert time.monotonic() < deadline
        time.sleep(.005)
    assert not sup._pending_calls


@pytest.mark.parametrize('adapter', ['payment', 'code'])
@pytest.mark.parametrize('terminal', ['cancel', 'expiry'])
def test_child_disposal_survives_stalled_loop(transport, monkeypatch, adapter, terminal):
    from secure_env_ingress import bound_cdp, payment_fill as pf, nested_code as nc
    sup, wire, replacement, sessions = transport
    batch = threading.Event()
    with bound_cdp.acquisition_scope(batch):
        transport_cdp = bound_cdp.BoundCDP(sup)
    child = transport_cdp.call('Target.attachToTarget', {'targetId': 'child', 'flatten': True})['result']['sessionId']
    if adapter == 'payment':
        owner = pf._Attachment(transport_cdp, child)
        def cleanup():
            owner.drop(None)
    else:
        owner = nc._Lease(transport_cdp)
        owner.sessions.append(child)
        cleanup = owner.close
    monkeypatch.setattr(bound_cdp, 'CALL_TIMEOUT', .03)
    wire.detach_delay = .05
    entered, resume = threading.Event(), threading.Event()
    def stall():
        entered.set()
        resume.wait(2)
    sup._loop.call_soon_threadsafe(stall)
    assert entered.wait(1)
    if terminal == 'cancel':
        batch.set()
    try:
        cleanup()  # Must return before the captured loop resumes.
        assert child in sessions
        sup._ws = replacement
    finally:
        resume.set()
    deadline = time.monotonic() + 1
    while child in sessions or sup._pending_calls:
        assert time.monotonic() < deadline
        time.sleep(.005)
    assert set(sessions) == {'default', 'sibling'}
    assert not replacement.commands
    detached = [c['params']['sessionId'] for c in wire.commands if c['method'] == 'Target.detachFromTarget']
    assert detached == [child]
    sup._ws = wire
    assert bound_cdp.BoundCDP(sup).call('Target.getTargetInfo', {}, 'default')['result']['targetInfo']['targetId'] == 'other'


@pytest.mark.parametrize('adapter', ['payment', 'code'])
@pytest.mark.parametrize('failure', ['close-error', 'caller-timeout'])
def test_guard_release_is_independent_and_timeout_owned(transport, monkeypatch, adapter, failure):
    from secure_env_ingress import bound_cdp, payment_fill as pf, nested_code as nc
    sup, wire, replacement, _ = transport
    batch = threading.Event()
    with bound_cdp.acquisition_scope(batch):
        captured = bound_cdp.BoundCDP(sup)
    original_send = wire.send
    async def send(raw):
        msg = json.loads(raw)
        if msg['method'] == 'Runtime.callFunctionOn':
            if failure == 'close-error':
                wire.commands.append(msg)
                raise ValueError('synthetic close failure')
            await asyncio.sleep(.05)
        await original_send(raw)
    wire.send = send
    batch.set()
    monkeypatch.setattr(bound_cdp, 'CALL_TIMEOUT', .03)
    entered, resume = threading.Event(), threading.Event()
    def stall():
        entered.set()
        resume.wait(2)
    if failure == 'caller-timeout':
        sup._loop.call_soon_threadsafe(stall)
        assert entered.wait(1)
    try:
        if adapter == 'payment':
            pf.release(SimpleNamespace(supervisor=captured, parent_sid='default', child_sid='default',
                parent_guard='exact-parent', child_guard='exact-guard', attachment=None, parent_session=None))
        else:
            owner = nc._Lease(captured)
            owner.keep('default', 'exact-guard')
            owner.discard('default', 'exact-guard')
        sup._ws = replacement
    finally:
        resume.set()
    deadline = time.monotonic() + 1
    expected_objects = ['exact-parent', 'exact-guard'] if adapter == 'payment' else ['exact-guard']
    while len([c for c in wire.commands if c['method'] == 'Runtime.releaseObject']) < len(expected_objects) or sup._pending_calls:
        assert time.monotonic() < deadline
        time.sleep(.005)
    assert len(wire.commands) == 2 * len(expected_objects)
    for obj in expected_objects:
        calls = [c for c in wire.commands if c['params']['objectId'] == obj]
        assert [c['method'] for c in calls] == ['Runtime.callFunctionOn', 'Runtime.releaseObject']
        assert all(c['sessionId'] == 'default' for c in calls)
    assert not replacement.commands
    with pytest.raises(ValueError, match='cancelled'):
        captured.call('Runtime.callFunctionOn', {'objectId': 'exact-guard', 'functionDeclaration': 'function(){this.write(0,"x")} '}, 'default')
    assert not replacement.commands


def test_failure_after_attach_disposes_exact_session(transport, monkeypatch):
    sup, _, _, sessions = transport
    monkeypatch.setattr(ps.ParentSession, 'check', lambda _: (_ for _ in ()).throw(ValueError('post attach')))
    with pytest.raises(ValueError, match='post attach'):
        ps.ParentSession(sup, 'parent')
    assert set(sessions) == {'default', 'sibling'}
