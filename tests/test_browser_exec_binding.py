"""Browser Use compatibility binding through fresh public captured handles."""
import pytest

from public_capture_helpers import PublicConnection, install_public_registry
from secure_env_ingress.vault_ingress import assert_browser_target, capture_browser_target


@pytest.mark.parametrize('name', ['', 'named-a', 'named-b'])
def test_browser_exec_uses_existing_task_supervisor_not_legacy_cache(monkeypatch, name):
    from tools import browser_tool, browser_use_cli

    # This compatibility mode deliberately does not prove BU_NAME. It binds
    # the existing task connection and page, not legacy browser-tool records.
    evaluated = []
    connections = {}
    for active_name in ('named-a', 'named-b'):
        connections[active_name] = PublicConnection(
            cdp_url=f'ws://synthetic-{active_name}',
            page_session_id=f'page-{active_name}',
            evaluate=lambda expr: evaluated.append(expr) or 'https://site.test/login',
        )
    connection = connections[name or 'named-a']
    registry = install_public_registry(monkeypatch, connection)
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    monkeypatch.setattr(browser_tool, '_active_sessions', {
        'task': {'owner_task_id': 'task', 'session_key': 'task'},
    })
    monkeypatch.setattr(browser_tool, '_last_active_session_key', {'task': 'task'})
    target = capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    assert target.browser_backend == 'browser-use' and target.browser_key == ''
    original = registry.handles[0]
    assert_browser_target(target)
    assert evaluated == ['location.href', 'location.href']
    assert all(handle.is_valid() for handle in registry.handles)
    # New wrapper objects for one live connection are not page/connection drift.
    assert len(registry.handles) > 1
    assert len(original.calls) == 2
    assert not any(handle.calls for handle in registry.handles[1:])

    registry.connection = connections['named-b' if name != 'named-b' else 'named-a']
    with pytest.raises(ValueError):
        assert_browser_target(target)
    registry.connection = connection
    connection.page_session_id = 'changed'
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    connection.page_session_id = target.page_session_id
    connection.evaluate = lambda expr: 'https://other.test/login'
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    connection.evaluate = lambda expr: 'https://site.test/login'
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: False)
    with pytest.raises(ValueError, match='browser backend changed'):
        assert_browser_target(target)


@pytest.mark.parametrize('case', ['original_invalid', 'replacement', 'fresh_invalid'])
def test_invalid_original_or_current_capture_cannot_retarget(monkeypatch, case):
    from tools import browser_use_cli
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    registry = install_public_registry(monkeypatch)
    target = capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    original = registry.handles[0]
    sent = len(original.calls)
    if case == 'original_invalid':
        original.valid = False
    elif case == 'replacement':
        # Identical task, endpoint, page and origin cannot rescue a stale wire.
        registry.connection = PublicConnection()
    else:
        registry.capture_valid = False
    fresh = registry.capture('task')
    assert original.is_valid() is (case == 'fresh_invalid')
    assert fresh.is_valid() is (case != 'fresh_invalid')
    with pytest.raises(ValueError):
        assert_browser_target(target)
    assert len(original.calls) == sent
    assert not fresh.calls
    assert not any(handle.calls for handle in registry.handles[1:])


@pytest.mark.parametrize('capability', ['capture', 'is_valid', 'call'])
def test_missing_public_capture_capability_fails_closed(monkeypatch, capability):
    from tools import browser_supervisor, browser_use_cli
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    registry = install_public_registry(monkeypatch)
    if capability == 'capture':
        monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'capture', None)
    else:
        capture = registry.capture

        def incomplete(task_id, **kwargs):
            handle = capture(task_id, **kwargs)
            setattr(handle, capability, None)
            return handle

        monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'capture', incomplete)
    with pytest.raises(ValueError):
        capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    assert not registry.connection.calls


def test_legacy_target_rejects_backend_switch(monkeypatch):
    from tools import browser_tool, browser_use_cli
    install_public_registry(monkeypatch)
    monkeypatch.setattr(browser_tool, '_active_sessions', {
        'task': {'owner_task_id': 'task', 'session_key': 'task'}})
    monkeypatch.setattr(browser_tool, '_last_active_session_key', {'task': 'task'})
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: False)
    target = capture_browser_target('https://site.test', 'Site', 'task', 'task', 'chat-key')
    assert_browser_target(target)
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    with pytest.raises(ValueError, match='browser backend changed'):
        assert_browser_target(target)
