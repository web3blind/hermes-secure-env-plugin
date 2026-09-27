"""Browser Use cannot issue a Vault link without native session/endpoint proof."""
import threading
from types import SimpleNamespace

import pytest

from secure_env_ingress.vault_ingress import VaultTarget, assert_browser_target, capture_browser_target


@pytest.mark.parametrize('name', ['', 'named-a', 'named-b'])
def test_browser_exec_does_not_trust_task_supervisor_or_legacy_cache(monkeypatch, name):
    from tools import browser_tool, browser_use_cli, browser_supervisor

    # The native supervisor can point at a different BU_NAME or CDP endpoint,
    # even when the visible URL happens to equal the requested origin.
    supervisor = SimpleNamespace(
        task_id='task', cdp_url='ws://synthetic-other-endpoint',
        _state_lock=threading.RLock(), _active=True, _page_session_id='first-page',
        evaluate_runtime=lambda expr: {'ok': True, 'result': 'https://site.test/login'},
    )
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    monkeypatch.setattr(browser_tool, '_active_sessions', {
        'task': {'owner_task_id': 'task', 'session_key': 'task'},
    })
    monkeypatch.setattr(browser_tool, '_last_active_session_key', {'task': 'task'})
    with pytest.raises(ValueError, match='session binding unavailable'):
        capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    # Existing capabilities created by the prior implementation must also fail
    # closed on submission, not merely at issuance.
    stale = VaultTarget('https://site.test', 'Site', 'task', '', id(supervisor),
                        'task', 'chat-key', id(supervisor), 'first-page', 'browser-use')
    with pytest.raises(ValueError, match='session binding unavailable'):
        assert_browser_target(stale)


def test_legacy_target_rejects_backend_switch(monkeypatch):
    from tools import browser_tool, browser_use_cli, browser_supervisor
    supervisor = SimpleNamespace(task_id='task', _state_lock=threading.RLock(),
        _active=True, _page_session_id='page',
        evaluate_runtime=lambda expr: {'ok': True, 'result': 'https://site.test/login'})
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    monkeypatch.setattr(browser_tool, '_active_sessions', {
        'task': {'owner_task_id': 'task', 'session_key': 'task'}})
    monkeypatch.setattr(browser_tool, '_last_active_session_key', {'task': 'task'})
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: False)
    target = capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    assert_browser_target(target)
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    with pytest.raises(ValueError, match='browser backend changed'):
        assert_browser_target(target)
