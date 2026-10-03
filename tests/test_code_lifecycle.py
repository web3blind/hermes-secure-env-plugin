"""Exact shutdown/cancellation/expiry ownership; no live browser or credentials."""
from contextvars import copy_context
import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from secure_env_ingress import code_targets as c
from test_code_selection import target


def test_close_terminal_and_queued_chooser(monkeypatch):
    picker = c.CodeSelection()
    calls = []
    monkeypatch.setattr(c, 'discover', lambda *a: calls.append(True) or [target()])
    picker.close()
    with pytest.raises(ValueError):
        picker.choose(('scope',), 'https://example.test', 'Fixture', 'task')
    assert not calls

    picker = c.CodeSelection()
    candidates = [target(), target('B')]
    monkeypatch.setattr(c, 'discover', lambda *a: candidates)
    picker.choose(('scope',), candidates[0].origin, 'Fixture', 'task')
    ready, proceed, attempted = threading.Event(), threading.Event(), threading.Event()
    retired, errors = [], []
    def release(candidate):
        ready.set()
        assert proceed.wait(5)
        retired.append(candidate)
    monkeypatch.setattr(c, 'release', release)
    closer = threading.Thread(target=picker.close)
    closer.start()
    assert ready.wait(5)  # Closed flag set; close still holds the selection lock.
    def queued():
        attempted.set()
        try:
            picker.choose(('scope',), candidates[0].origin, 'Fixture', 'task')
        except ValueError:
            errors.append(True)
    chooser = threading.Thread(target=queued)
    chooser.start()
    assert attempted.wait(5) and chooser.is_alive()
    proceed.set()
    closer.join(5)
    chooser.join(5)
    assert errors == [True] and retired == candidates and not picker._entries


def test_close_during_discovery_retires_exact_result(monkeypatch):
    picker = c.CodeSelection()
    ready, proceed = threading.Event(), threading.Event()
    retired, errors = [], []
    candidate = target()
    def discover(*a):
        ready.set()
        assert proceed.wait(5)
        return [candidate]
    monkeypatch.setattr(c, 'discover', discover)
    monkeypatch.setattr(c, 'release', retired.append)
    def run():
        try:
            picker.choose(('scope',), candidate.origin, candidate.label, 'task')
        except ValueError:
            errors.append(True)
    worker = threading.Thread(target=run)
    worker.start()
    assert ready.wait(5)
    closer = threading.Thread(target=picker.close)
    closer.start()
    closer.join(.5)
    stopped = not closer.is_alive()
    proceed.set()
    closer.join(5)
    worker.join(5)
    assert stopped and errors == [True] and retired == [candidate]


def test_abandoned_batch_expires_without_another_call(monkeypatch):
    picker = c.CodeSelection()
    picker.ttl_seconds = .05
    candidates = [target(), target('B')]
    retired = []
    monkeypatch.setattr(c, 'discover', lambda *a: candidates)
    monkeypatch.setattr(c, 'release', retired.append)
    try:
        _, response = picker.choose(('scope',), candidates[0].origin, 'Fixture', 'task')
        assert len(response['candidates']) == 2
        deadline = time.monotonic() + 2
        while len(retired) < 2 and time.monotonic() < deadline:
            time.sleep(.01)
        assert retired == candidates
        assert not picker._entries
    finally:
        picker.close()


def test_old_cancel_never_retires_newer_batch(monkeypatch):
    picker = c.CodeSelection()
    old, newer = threading.Event(), threading.Event()
    a, b = [target(), target('A2')], [target('B'), target('B2')]
    retired = []
    results = iter([a, b])
    monkeypatch.setattr(c, 'discover', lambda *a: next(results))
    monkeypatch.setattr(c, 'release', retired.append)
    try:
        picker.choose(('scope',), a[0].origin, 'Fixture', 'task', batch=old)
        _, response = picker.choose(('scope',), b[0].origin, 'Fixture', 'task', batch=newer)
        assert retired == a
        picker.cancel_batch(old)
        assert retired == a and len(picker._entries) == 2
        monkeypatch.setattr(c, 'assert_target', lambda t: None)
        selected, _ = picker.choose(('scope',), b[0].origin, 'Fixture', 'task', response['candidates'][0]['selection'])
        assert selected is b[0]
        c.release(selected)
    finally:
        picker.close()
    assert retired == a + b


def test_completed_private_guard_retires_while_sibling_lives(monkeypatch):
    from secure_env_ingress import nested_code as n
    lease = n._Lease(None)
    lease.refs = 2
    lease.objects = [('sid', 'shared'), ('sid', 'first'), ('sid', 'second')]
    invoked, released = [], []
    monkeypatch.setattr(n, '_invoke', lambda *a: invoked.append(a[2]) or {})
    monkeypatch.setattr(n, '_call', lambda s, m, p, sid=None: released.append((m, p)))
    n.release(SimpleNamespace(lease=lease, leaf_guard='first', leaf_sid='sid'))
    assert invoked == ['first']
    assert lease.objects == [('sid', 'shared'), ('sid', 'second')]
    assert lease.refs == 1 and not lease.closed
    n.release(SimpleNamespace(lease=lease, leaf_guard='second', leaf_sid='sid'))
    assert lease.closed and invoked == ['first', 'second', 'shared']
    assert len(released) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['unload', 'unload-returned', 'cancel-single', 'cancel-multiple', 'repeat-cancel'])
async def test_registered_late_discovery_terminal_cleanup(tmp_path, monkeypatch, case):
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress import plugin
    from secure_env_ingress.nested_code import NestedCodeTarget, _Lease
    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    ready, proceed = threading.Event(), threading.Event()
    lease = _Lease(None)
    count = 2 if case in ('cancel-multiple', 'repeat-cancel') else 1
    lease.refs = count
    targets = [NestedCodeTarget('https://example.test', 'Synthetic', 'task', 'p', 'nonce', 'https://example.test',
        (SimpleNamespace(control=SimpleNamespace(form_index=i)),), None, leaf_guard=str(i), lease=lease,
        parent='p', frame='f') for i in range(count)]
    def discover(*a, **k):
        ready.set()
        assert proceed.wait(5)
        return targets
    monkeypatch.setattr(c, 'discover', discover)
    if case == 'unload-returned':
        # A worker that already owns an automatic result is not in the cache.
        monkeypatch.setattr(c.CodeSelection, 'choose', lambda *a, **k: (discover()[0], None))
    created = []
    monkeypatch.setattr(plugin, 'LazyRuntime', lambda *a: created.append(True))
    retired = []
    original = c.release
    def release(t):
        retired.append(t)
        original(t)
    monkeypatch.setattr(c, 'release', release)
    with registered(monkeypatch, home, settings=settings) as (ctx, gateway), _profile_runtime_scope(home, {}):
        from gateway.config import Platform
        from gateway.platforms.event import MessageEvent
        from gateway.session import SessionSource
        from hermes_cli.lifecycle import invoke_hook
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='7', chat_type='dm'), text='synthetic')
        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7', chat_type='dm', session_id='task', session_key='key', profile='', cron_session='')
        try:
            handler = registry.get_entry('browser_vault', scope=str(home)).handler
            worker = asyncio.create_task(handler(dict(origin=targets[0].origin, label='Synthetic', mode='code', parent='p'), task_id='task'))
            assert await asyncio.to_thread(ready.wait, 5)
            if case.startswith('unload'):
                # PluginContext stores the exact registered unload callback.
                await asyncio.to_thread(ctx.unload)
            else:
                worker.cancel()
                await asyncio.sleep(0)
                if case == 'repeat-cancel':
                    worker.cancel()
                    await asyncio.sleep(0)
            proceed.set()
            if case.startswith('unload'):
                result = await worker
                assert 'unavailable' in result
            else:
                with pytest.raises(asyncio.CancelledError):
                    await worker
            deadline = time.monotonic() + 2
            while not lease.closed and time.monotonic() < deadline:
                await asyncio.sleep(.01)
            assert lease.closed and not created
            assert retired == targets
        finally:
            proceed.set()
            sc.clear_session_vars(tokens)


@pytest.mark.parametrize('order', ['cancel_first', 'complete_first', 'take_first', 'exception'])
def test_choice_atomic_ownership_orders(monkeypatch, order):
    from secure_env_ingress.plugin import _CodeChoice
    selected = target('selected')
    batch = threading.Event()
    retired, cancelled = [], []
    done = threading.Event()
    def release(t):
        retired.append(t)
        done.set()
    monkeypatch.setattr(c, 'release', release)
    def choose(*a, **k):
        if order == 'exception':
            raise ValueError('synthetic')
        return selected, None
    choice = _CodeChoice(SimpleNamespace(choose=choose, cancel_batch=cancelled.append), batch)
    if order in ('cancel_first', 'exception'):
        choice.cancel()
    if order == 'exception':
        with pytest.raises(ValueError):
            choice.run()
    else:
        assert choice.run() is None
    if order == 'take_first':
        assert choice.take() == (selected, None)
    choice.cancel()
    choice.cancel()
    if order in ('cancel_first', 'complete_first'):
        assert done.wait(3)
        assert retired == [selected]
    else:
        deadline = time.monotonic() + 3
        while not cancelled and time.monotonic() < deadline:
            time.sleep(.01)
        assert retired == []
    assert cancelled == [batch] and batch.is_set() and choice.result is None


def test_dispatcher_cancel_selected_worker_after_loop_closed(tmp_path, monkeypatch):
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress import plugin, nested_code as n
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook

    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    picker = c.CodeSelection()
    monkeypatch.setattr(plugin, 'CodeSelection', lambda: picker)
    lease = n._Lease(None)
    lease.refs = 2
    lease.objects = [('sid', 'shared'), ('sid', 'selected'), ('sid', 'sibling')]
    lease.sessions = ['sid']
    lease.resources = {guard: ({('sid', 'shared'), ('sid', guard)}, {'sid'})
                       for guard in ('selected', 'sibling')}
    values = {guard: ['synthetic-value'] for guard in ('selected', 'sibling')}
    closed_guards, released_objects, detached = [], [], []
    def invoke(sup, sid, obj, *a):
        closed_guards.append(obj)
        if obj in values:
            values[obj].clear()
        return {}
    def call(sup, method, params, sid=None):
        if method == 'Runtime.releaseObject':
            released_objects.append(params['objectId'])
        if method == 'Target.detachFromTarget':
            detached.append(params['sessionId'])
        return {}
    monkeypatch.setattr(n, '_invoke', invoke)
    monkeypatch.setattr(n, '_call', call)
    targets = [n.NestedCodeTarget('https://example.test', 'Synthetic', 'task', 'p', 'nonce',
        'https://example.test', (SimpleNamespace(control=SimpleNamespace(form_index=i)),), None,
        leaf_guard=guard, leaf_sid='sid', lease=lease, parent='p', frame='f')
        for i, guard in enumerate(('selected', 'sibling'))]
    newer_targets = [target('new'), target('new2')]
    batches = iter([targets, newer_targets])
    monkeypatch.setattr(c, 'discover', lambda *a, **k: next(batches))
    ready, proceed, retired = threading.Event(), threading.Event(), threading.Event()
    releases = []
    original_release = c.release
    def release(t):
        releases.append(t)
        original_release(t)
        if t is targets[0]:
            retired.set()
    monkeypatch.setattr(c, 'release', release)
    def validate(t):
        assert t is targets[0]
        assert all(entry[2] is not t for entry in picker._entries.values())
        ready.set()
        assert proceed.wait(10)
    monkeypatch.setattr(c, 'assert_target', validate)
    issued = []
    monkeypatch.setattr(plugin, 'LazyRuntime', lambda *a: issued.append(True))
    with registered(monkeypatch, home, settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='7', chat_type='dm'), text='synthetic')
        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7', chat_type='dm', session_id='task', session_key='key', profile='', cron_session='')
        loop = asyncio.new_event_loop()
        loop_closed = threading.Event()
        failures = []
        try:
            scope = (str(home), 'task', 'key', '7', '7', '')
            old, newer = threading.Event(), threading.Event()
            _, response = picker.choose(scope, targets[0].origin, 'Synthetic', 'task', parent='p', batch=old)
            picker.choose(('new-scope',), newer_targets[0].origin, 'Fixture', 'task', batch=newer)
            handler = registry.get_entry('browser_vault', scope=str(home)).handler
            async def run():
                await handler(dict(origin=targets[0].origin, label='Synthetic', mode='code', parent='p',
                    selection=response['candidates'][0]['selection']), task_id='task')
            def dispatcher():
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run())
                except asyncio.CancelledError:
                    pass
                except BaseException as exc:
                    failures.append(exc)
                finally:
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                    loop.close()
                    loop_closed.set()
            context = copy_context()
            thread = threading.Thread(target=lambda: context.run(dispatcher))
            thread.start()
            assert ready.wait(5)
            pending = asyncio.all_tasks(loop)
            assert len(pending) == 2  # Outer handler AND inner to_thread choice.
            for task in pending:
                loop.call_soon_threadsafe(task.cancel)
            assert loop_closed.wait(5)
            thread.join(5)
            assert loop.is_closed() and not failures
            proceed.set()  # No loop restart or subsequent tool invocation.
            assert retired.wait(3), 'selected thread result escaped retirement after loop closure'
            assert releases.count(targets[0]) == 1
            assert values['selected'] == [] and values['sibling'] == ['synthetic-value']
            assert closed_guards == ['selected'] and released_objects == ['selected']
            assert lease.refs == 1 and not lease.closed and not detached
            assert len(picker._entries) == 3 and not issued and not gateway.sent and not newer.is_set()
            picker.cancel_batch(old)
            assert lease.closed and values['sibling'] == []
            assert sorted(released_objects) == ['selected', 'shared', 'sibling']
            assert detached == ['sid'] and len(picker._entries) == 2
            assert all(entry[3] is newer for entry in picker._entries.values())
            picker.cancel_batch(newer)
            assert not picker._entries and releases == targets + newer_targets
        finally:
            proceed.set()
            sc.clear_session_vars(tokens)
