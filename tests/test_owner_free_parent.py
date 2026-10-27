"""Owner-free parent admission on the actual released captured transport."""
import importlib.util
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_parent_transport import transport as _transport
from secure_env_ingress import parent_session as ps
from secure_env_ingress.code_targets import _call
from secure_env_ingress.bound_cdp import acquisition_scope, dispatch_scope

transport = _transport


def test_stock_owner_module_absent_old_sibling_allowed(transport, tmp_path):
    host, wire, _, sessions = transport
    assert importlib.util.find_spec('tools.browser_tab_lifecycle') is None
    parent = ps.ParentSession(host.handle, 'parent')
    try:
        assert parent.check() == parent.sid
        assert sessions[parent.sid] == 'parent'
        assert host._page_session_id == 'default'
    finally:
        parent.drop(None)
    assert set(sessions) == {'default', 'sibling'}
    assert not list(tmp_path.rglob('browser_tabs.sqlite'))


@pytest.mark.parametrize('change', ['cancel', 'expiry', 'human_epoch'])
def test_original_queued_dispatch_refused(transport, monkeypatch, change):
    host, wire, _, _ = transport
    from tools import browser_vault_tool
    from tools.bot_desktop import lease
    monkeypatch.setattr(browser_vault_tool, '_bot_desktop_browser_session', lambda task: True)
    cancelled = threading.Event()
    with acquisition_scope(cancelled):
        parent = ps.ParentSession(host.handle, 'parent')
    entered, resume = threading.Event(), threading.Event()
    def stall():
        entered.set()
        resume.wait(2)
    host._loop.call_soon_threadsafe(stall)
    assert entered.wait(1)
    before = len(wire.commands)
    def command():
        with dispatch_scope(time.monotonic() + (.08 if change == 'expiry' else 5)):
            return _call(parent.transport, 'Runtime.evaluate', {'expression': 'synthetic'}, parent.sid)
    try:
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(command)
            time.sleep(.12)
            if change == 'cancel':
                cancelled.set()
            elif change == 'human_epoch':
                lease.acquire('synthetic-viewer', profile_key=str(parent.home))
                lease.release('synthetic-viewer', profile_key=str(parent.home))
            resume.set()
            with pytest.raises(ValueError):
                future.result(2)
        assert len(wire.commands) == before
    finally:
        resume.set()
        parent.drop(None)


def test_no_parent_discovery_refuses_without_capture(monkeypatch):
    from secure_env_ingress import code_targets as ct
    called = []
    monkeypatch.setattr(ct, '_supervisor', lambda *a: called.append(True))
    with pytest.raises(ValueError, match='explicit parent required'):
        ct.discover('https://a.test', 'Synthetic', 'task')
    assert not called


def test_no_parent_cannot_replay_a_legacy_selection(monkeypatch):
    from types import SimpleNamespace
    from secure_env_ingress import code_targets as ct
    picker=ct.CodeSelection()
    target=SimpleNamespace(origin='https://a.test',label='Synthetic',task='task',
                           explicit_parent=False,field_selector=None,target_spec=None)
    reached=[]
    monkeypatch.setattr(ct,'assert_target',lambda target:reached.append(True))
    monkeypatch.setattr(ct,'release',lambda target:None)
    picker._entries['legacy-selection']=(time.monotonic()+120,'scope',target,threading.Event())
    try:
        with pytest.raises(ValueError,match='explicit parent required'):
            picker.choose('scope','https://a.test','Synthetic','task',selection='legacy-selection')
        assert not reached
    finally:
        picker.close()
