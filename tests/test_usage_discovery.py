"""Discover both secret-entry modes and the bundled skill via real registration."""
import json
import pytest
from secure_env_ingress import code_targets as codes

from generic_helpers import registered
from gateway.run import _profile_runtime_scope
from test_runtime_e2e import make_runtime
from tools.registry import registry
from tools.skills_tool import skill_view


def test_registered_usage_and_both_modes(tmp_path, monkeypatch):
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        entry = registry.get_entry('browser_vault', scope=str(home))
        description = entry.schema['description'].lower()
        for term in ('secure env', 'login', 'username', 'password', 'code', 'passcode', 'payment', 'confirmation', 'prompt_unavailable'):
            assert term in description
        assert set(entry.schema['parameters']['properties']['mode']['enum']) == {'login', 'code', 'payment'}
        assert 'mode' not in entry.schema['parameters']['required']
        assert 'parent' in entry.schema['parameters']['properties']
        for mode, parent in [('login', 'chosen'), ('payment', 'chosen'), ('code', None), ('code', ''), ('code', 123)]:
            refused = json.loads(registry.dispatch('browser_vault', {
                'origin': 'https://example.test', 'label': 'Synthetic', 'mode': mode, 'parent': parent},
                task_id='synthetic', session_id='synthetic'))
            assert refused['success'] is False and refused['reason'] == 'session_binding'
        result = json.loads(skill_view('secure-env-ingress:usage'))
        assert result['success'], result
        assert result['content']


@pytest.mark.asyncio
async def test_cancelled_discovery_releases_late_exact_target(tmp_path, monkeypatch):
    import asyncio
    import threading
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress.nested_code import NestedCodeTarget, _Lease
    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    lease = _Lease(None)
    lease.refs = 1
    target = NestedCodeTarget('https://example.test', 'Synthetic', 'task', 'p', 'nonce', 'https://example.test', (), None, leaf_guard='guard', lease=lease)
    ready, proceed, done = threading.Event(), threading.Event(), threading.Event()
    def choose(*args, **kwargs):
        ready.set()
        assert proceed.wait(5)
        done.set()
        return target, None
    monkeypatch.setattr(codes.CodeSelection, 'choose', choose)
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7', chat_type='dm', session_id='task', session_key='key', profile='', cron_session='')
        try:
            handler = registry.get_entry('browser_vault', scope=str(home)).handler
            worker = asyncio.create_task(handler(dict(origin=target.origin, label=target.label, mode='code', parent='p'), task_id='task'))
            assert await asyncio.to_thread(ready.wait, 5)
            worker.cancel()
            await asyncio.sleep(0)
            proceed.set()
            with pytest.raises(asyncio.CancelledError):
                await worker
            assert await asyncio.to_thread(done.wait, 5)
            # Cleanup owns the late worker independently of the cancelled caller.
            for _ in range(200):
                if lease.closed:
                    break
                await asyncio.sleep(.01)
            assert lease.closed
        finally:
            sc.clear_session_vars(tokens)
