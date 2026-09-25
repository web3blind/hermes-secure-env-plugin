"""Synthetic login ingress exercised against native encrypted Vault and actual HTTPS server."""
from urllib.parse import urlsplit

import pytest

from test_runtime_e2e import make_runtime, post
from secure_env_ingress.vault_ingress import VaultTarget, strict_origin, capture_browser_target



@pytest.mark.parametrize('origin', ['http://site.test', 'https://site.test/', 'https://site.test:443',
    'https://SITE.test', 'https://site.test/a', 'https://site.test?x=1',
    'https://user@site.test', 'https://site.test#x', 'https://site.test:broken'])
def test_strict_origin_rejects_malformed(origin):
    with pytest.raises(ValueError):
        strict_origin(origin)


def test_capture_requires_existing_task_owned_browser(monkeypatch):
    from tools import browser_tool as bt
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    from secure_env_ingress.vault_ingress import assert_browser_target
    import threading
    class Supervisor:
        task_id = 'task-1'
        _state_lock = threading.Lock()
        _active = True
        _page_session_id = 'page-1'
        href = 'https://site.test/login'
        def evaluate_runtime(self, expression):
            return {'ok': True, 'result': self.href}
    supervisor = Supervisor()
    monkeypatch.setattr(SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    monkeypatch.setattr(bt, '_last_active_session_key', {})
    monkeypatch.setattr(bt, '_active_sessions', {})
    with pytest.raises(ValueError, match='browser missing'):
        capture_browser_target('https://site.test', 'Site', 'task-1', 'task-1', 'session-key')
    with pytest.raises(ValueError, match='unbound task'):
        capture_browser_target('https://site.test', 'Site', 'default', 'default', 'session-key')
    record = {'session_key': 'task-1', 'owner_task_id': 'task-1'}
    bt._active_sessions['task-1'] = record
    bt._last_active_session_key['task-1'] = 'task-1'
    target = capture_browser_target('https://site.test', 'Site', 'task-1', 'task-1', 'session-key')
    assert_browser_target(target)
    supervisor.href = 'https://elsewhere.test/login'
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    supervisor.href = 'https://site.test/login'
    supervisor._page_session_id = 'page-2'
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    supervisor._page_session_id = 'page-1'
    monkeypatch.setattr(SUPERVISOR_REGISTRY, 'get', lambda task: Supervisor())
    with pytest.raises(ValueError, match='page changed'):
        assert_browser_target(target)
    monkeypatch.setattr(SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    bt._active_sessions['task-1'] = record.copy()
    with pytest.raises(ValueError, match='browser changed'):
        assert_browser_target(target)


def test_native_encrypted_vault_https_roundtrip_and_replay(tmp_path, monkeypatch, caplog):
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    from secure_env_ingress import runtime as module
    monkeypatch.setattr(module, 'assert_browser_target', lambda target: None)
    target = VaultTarget('https://site.test', 'Synthetic site', 'task', 'task', 123, 'task', 'key')
    from agent.vault_store import VaultStore
    try:
        with pytest.raises(Exception):
            runtime.create_vault(99, target)
        links = runtime.create_vault(('telegram', '7'), target)
        status_text = runtime.status()
        assert 'an active session exists' in status_text
        token = urlsplit(links['url']).fragment
        status, info = post(cfg, root, '/session', {'token': token, 'initData': ''})
        assert status == 200 and info['kind'] == 'browser_vault'
        assert info['keys'] == ['Username', 'Password']
        secret = 'fixture-${VAULT}-password'
        status, result = post(cfg, root, '/submit', {'token': token, 'initData': '',
                                                   'values': ['alice@example.test', secret]})
        assert status == 200 and result == {'saved': True}
        assert not (home / '.env').exists()
        store = VaultStore(home / 'vault')
        meta = store.list_items()[0]
        assert meta.identifier == 'alice@example.test' and meta.identifier_type == 'username'
        assert meta.origin == target.origin and meta.kind == 'login'
        assert store.resolve_secret(meta.id) == {'password': secret}
        from tools.browser_vault_tool import browser_vault_list
        import json
        native = json.loads(browser_vault_list())
        assert any(item['handle'] == meta.id and item['identifier'] == 'alice@example.test'
                   and item['origin'] == target.origin for item in native['items'])
        assert secret not in json.dumps(native)
        from agent.vault_backends import backend_for_handle
        backend = backend_for_handle(meta.id)
        assert backend is not None and backend.get_meta(meta.id).origin == target.origin
        assert backend.resolve_password(meta.id) == secret
        assert secret.encode() not in (home / 'vault' / 'vault.json.enc').read_bytes()
        assert (home / 'vault' / 'vault.json.enc').stat().st_mode & 0o777 == 0o600
        # After consumption the on-demand listener may already be closed.
        # Both an HTTP 410 and connection refusal are valid transport outcomes;
        # the backend must still reject replay and keep the original item only.
        from secure_env_ingress.server import HTTPError
        with pytest.raises(HTTPError) as replay:
            runtime.submit(token, '', ['bob', 'other'])
        assert replay.value.status == 410
        try:
            status, _ = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': ['bob', 'other']})
        except ConnectionRefusedError:
            status = None
        assert status in (410, None) and len(store.list_items()) == 1
        assert secret not in caplog.text and token not in caplog.text
    finally:
        runtime.close()


def test_invalid_input_terminal_and_wrong_page_or_profile(tmp_path, monkeypatch):
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    from secure_env_ingress import runtime as module
    target = VaultTarget('https://site.test', 'Site', 'task', 'task', 7, 'task', 'key')
    monkeypatch.setattr(module, 'assert_browser_target', lambda target: None)
    try:
        links = runtime.create_vault(('telegram', '7'), target)
        token = urlsplit(links['url']).fragment
        status, _ = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': ['name', 'bad\npassword']})
        assert status == 400
        assert post(cfg, root, '/session', {'token': token, 'initData': ''})[0] == 410
        monkeypatch.setattr(module, 'assert_browser_target', lambda target: (_ for _ in ()).throw(ValueError('page changed')))
        assert not (home / 'vault' / 'vault.json.enc').exists()
        with pytest.raises(ValueError):
            runtime.create_vault(('telegram', '7'), target)
        monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'other-profile'))
        with pytest.raises(ValueError):
            runtime.create_vault(('telegram', '7'), target)
    finally:
        runtime.close()


def test_two_profiles_remain_isolated(tmp_path):
    from agent.vault_store import VaultStore
    first, second = [tmp_path / name for name in ('one', 'two')]
    for path in (first, second):
        store = VaultStore(path / 'vault')
        store.add_item('login', 'Site', {'identifier_type': 'username', 'identifier': 'fixture', 'password': 'fixture-pass'}, origin='https://site.test')
    assert (first / 'vault' / 'vault.key').read_bytes() != (second / 'vault' / 'vault.key').read_bytes()
    assert len(VaultStore(first / 'vault').list_items()) == len(VaultStore(second / 'vault').list_items()) == 1
