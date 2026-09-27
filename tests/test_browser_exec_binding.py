"""Browser Use compatibility binding: task supervisor, not exact named tab."""
import threading
from types import SimpleNamespace

import pytest

from secure_env_ingress.vault_ingress import assert_browser_target, capture_browser_target


@pytest.mark.parametrize('name', ['', 'named-a', 'named-b'])
def test_browser_exec_uses_existing_task_supervisor_not_legacy_cache(monkeypatch, name):
    from tools import browser_tool, browser_use_cli, browser_supervisor

    # The supervisor could be attached to a DIFFERENT named session on the
    # same origin. This compatibility mode deliberately does not prove BU_NAME.
    evaluated = []
    supervisors = {}
    for active_name in ('named-a', 'named-b'):
        supervisors[active_name] = SimpleNamespace(
            task_id='task', cdp_url=f'ws://synthetic-{active_name}',
            _state_lock=threading.RLock(), _active=True,
            _page_session_id=f'page-{active_name}',
            evaluate_runtime=lambda expr: evaluated.append(expr) or
                {'ok': True, 'result': 'https://site.test/login'},
        )
    supervisor = supervisors[name or 'named-a']
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    monkeypatch.setattr(browser_tool, '_active_sessions', {
        'task': {'owner_task_id': 'task', 'session_key': 'task'},
    })
    monkeypatch.setattr(browser_tool, '_last_active_session_key', {'task': 'task'})
    target = capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    assert target.browser_backend == 'browser-use' and target.browser_key == ''
    assert_browser_target(target)
    assert evaluated == ['location.href', 'location.href']
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get',
                        lambda task: supervisors['named-b' if name != 'named-b' else 'named-a'])
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    supervisor._page_session_id = 'changed'
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    supervisor._page_session_id = target.page_session_id
    supervisor.evaluate_runtime = lambda expr: {'ok': True, 'result': 'https://other.test/login'}
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    supervisor.evaluate_runtime = lambda expr: {'ok': True, 'result': 'https://site.test/login'}
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: False)
    with pytest.raises(ValueError, match='browser backend changed'):
        assert_browser_target(target)


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
