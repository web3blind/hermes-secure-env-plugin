"""Payment candidate lifetime does not depend on another tool call/event loop."""
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from types import SimpleNamespace

import pytest
from secure_env_ingress import payment_fill as pf


def candidates(deadline):
    return [SimpleNamespace(parent='parent', frame='frame', origin='https://synthetic.test', form_index=i, expires=deadline) for i in range(2)]


def test_idle_candidates_expire_autonomously(monkeypatch):
    found, released = candidates(time.monotonic() + .1), []
    done = threading.Event()
    monkeypatch.setattr(pf, 'discover', lambda *a: found)
    def release(t):
        released.append(t)
        if len(released) == 2:
            done.set()
    monkeypatch.setattr(pf, 'release', release)
    picker = pf.PaymentSelection()
    try:
        _, response = picker.choose('scope', 'task', 'parent', 'https://synthetic.test', 'vault_test')
        assert len(response['candidates']) == 2
        assert done.wait(1)
        assert released == found and not picker._entries
    finally:
        picker.close()


def test_consumed_sibling_expires_without_choose(monkeypatch):
    found, released = candidates(time.monotonic() + .15), []
    done = threading.Event()
    monkeypatch.setattr(pf, 'discover', lambda *a: found)
    monkeypatch.setattr(pf, 'assert_target', lambda t: None)
    monkeypatch.setattr(pf, 'release', lambda t: (released.append(t), done.set()))
    picker = pf.PaymentSelection()
    try:
        _, response = picker.choose('scope', 'task', 'parent', 'https://synthetic.test', 'vault_test')
        selected, _ = picker.choose('scope', 'task', 'parent', 'https://synthetic.test', 'vault_test', response['candidates'][0]['selection'])
        assert selected is found[0]
        assert done.wait(1)
        assert released == [found[1]]
    finally:
        picker.close()


def test_cancelled_discovery_releases_only_its_batch(monkeypatch):
    found, released = candidates(time.monotonic() + 10), []
    entered, resume, batch = threading.Event(), threading.Event(), threading.Event()
    def discovery(*args):
        entered.set()
        assert resume.wait(2)
        return found
    monkeypatch.setattr(pf, 'discover', discovery)
    monkeypatch.setattr(pf, 'release', released.append)
    picker = pf.PaymentSelection()
    try:
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(picker.choose, 'scope', 'task', 'parent', 'https://synthetic.test', 'vault_test', batch=batch)
            assert entered.wait(1)
            picker.cancel_batch(batch)
            resume.set()
            with pytest.raises(ValueError, match='stopped'):
                future.result(1)
        assert released == found and not picker._entries
        newer = threading.Event()
        monkeypatch.setattr(pf, 'discover', lambda *a: candidates(time.monotonic() + 10))
        picker.choose('scope', 'task', 'parent', 'https://synthetic.test', 'vault_test', batch=newer)
        picker.cancel_batch(batch)
        assert len(picker._entries) == 2 and not newer.is_set()
    finally:
        resume.set()
        picker.close()


@pytest.mark.asyncio
async def test_registered_cancelled_multi_discovery_has_worker_cleanup(tmp_path, monkeypatch):
    import asyncio
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    found, released = candidates(time.monotonic() + 10), []
    entered, proceed, done = threading.Event(), threading.Event(), threading.Event()
    def discover(*args):
        entered.set()
        assert proceed.wait(3)
        return found
    def release(target):
        released.append(target)
        if len(released) == 2:
            done.set()
    monkeypatch.setattr(pf, 'discover', discover)
    monkeypatch.setattr(pf, 'release', release)
    monkeypatch.setattr(pf, 'payment_backend', lambda *args: object())
    try:
        with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
            from payment_consent_helpers import payment_consent
            with payment_consent('once', session='task'):
                handler = registry.get_entry('secure_payment_fill', scope=str(home)).handler
                request = asyncio.create_task(handler(dict(handle='vault_test', parent='parent', origin='https://synthetic.test'), task_id='task'))
                assert await asyncio.to_thread(entered.wait, 2)
                request.cancel()
                await asyncio.sleep(.01)
                request.cancel()  # Abandon even the shielded cleanup await.
                with pytest.raises(asyncio.CancelledError):
                    await request
                proceed.set()
                assert await asyncio.to_thread(done.wait, 2)
                assert released == found
    finally:
        proceed.set()
