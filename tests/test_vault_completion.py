"""Bounded login completion through the actual local TLS listener and native Vault."""
from urllib.parse import urlsplit

import pytest

from test_runtime_e2e import make_runtime, post
from secure_env_ingress.vault_ingress import VaultTarget


def target():
    return VaultTarget('https://site.test', 'Synthetic', 'task', 'task', 7, 'task', 'key')


def setup(tmp_path, monkeypatch):
    runtime, config, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr('secure_env_ingress.runtime.assert_browser_target', lambda target: None)
    return runtime, config, home, root


def token(links):
    return urlsplit(links['url']).fragment


def test_https_completion_only_after_native_metadata_readback(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    try:
        links = runtime.create_vault(('telegram', '7'), target())
        assert not links['completion'].done()
        status, result = post(config, root, '/submit', {'token': token(links), 'initData': '',
                                                      'values': ['synthetic-user', 'synthetic-secret']})
        assert (status, result) == (200, {'saved': True})
        from agent.vault_store import VaultStore
        meta = VaultStore(home / 'vault').list_items()[0]
        assert links['completion'].result() == {'status': 'saved', 'handle': meta.id,
                                                 'origin': 'https://site.test'}
        assert 'synthetic-secret' not in str(links['completion'].result())
    finally:
        runtime.close()


def test_supersession_exact_group_cancellation_and_unload(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    try:
        first = runtime.create_vault(('telegram', '7'), target())
        second = runtime.create_vault(('telegram', '7'), target())
        assert first['completion'].result() == {'status': 'superseded'}
        runtime.cancel_group(first['group_id'])
        assert not second['completion'].done()
        assert post(config, root, '/session', {'token': token(second), 'initData': ''})[0] == 200
        runtime.cancel_group(second['group_id'])
        assert second['completion'].result() == {'status': 'cancelled'}
        with pytest.raises(Exception):
            runtime.submit(token(second), '', ['name', 'pass'])
        third = runtime.create_vault(('telegram', '7'), target())
        runtime.close()
        assert third['completion'].result() == {'status': 'cancelled'}
        assert runtime._server is None
        assert not (home / 'vault' / 'vault.json.enc').exists()
    finally:
        runtime.close()


def test_http_authenticated_malformed_rejected_and_no_write(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    try:
        links = runtime.create_vault(('telegram', '7'), target())
        assert post(config, root, '/submit', {'token': token(links), 'initData': '',
                                              'values': ['name', 'bad\npassword']})[0] == 400
        assert links['completion'].result() == {'status': 'rejected'}
        assert not (home / 'vault' / 'vault.json.enc').exists()
    finally:
        runtime.close()


def test_prewrite_page_change_is_failed_not_unknown(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    try:
        links = runtime.create_vault(('telegram', '7'), target())
        monkeypatch.setattr('secure_env_ingress.runtime.assert_browser_target',
                            lambda target: (_ for _ in ()).throw(ValueError('page changed')))
        assert post(config, root, '/submit', {'token': token(links), 'initData': '',
                                              'values': ['name', 'password']})[0] == 409
        assert links['completion'].result() == {'status': 'failed'}
        assert not (home / 'vault' / 'vault.json.enc').exists()
    finally:
        runtime.close()


def test_native_raises_after_commit_is_unknown_not_unsaved(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    from agent.vault_store import VaultStore
    original = VaultStore.add_item
    def after_commit(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise RuntimeError('synthetic postcommit fault with secret-like text')
    monkeypatch.setattr(VaultStore, 'add_item', after_commit)
    try:
        links = runtime.create_vault(('telegram', '7'), target())
        assert post(config, root, '/submit', {'token': token(links), 'initData': '',
                                              'values': ['name', 'fixture-secret']})[0] == 409
        assert links['completion'].result() == {'status': 'unknown'}
        assert len(VaultStore(home / 'vault').list_items()) == 1
        assert 'fixture-secret' not in str(links['completion'].result())
    finally:
        runtime.close()


def test_http_worker_uses_named_profile_issuance_context_not_process_default(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    from gateway import session_context as sc
    default_home = tmp_path / 'default-profile'
    default_home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(default_home))
    bound = set_hermes_home_override(home)
    session = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7',
                                  session_id='task', session_key='key', profile='named',
                                  cron_session='')
    try:
        links = runtime.create_vault(('telegram', '7'), target())
    finally:
        sc.clear_session_vars(session)
        reset_hermes_home_override(bound)
    try:
        assert post(config, root, '/submit', {'token': token(links), 'initData': '',
                                              'values': ['named-user', 'named-secret']})[0] == 200
        assert links['completion'].result()['status'] == 'saved'
        assert (home / 'vault' / 'vault.json.enc').exists()
        assert not (default_home / 'vault').exists()
    finally:
        runtime.close()


def test_expiry_during_browser_precheck_prevents_late_write(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    try:
        links = runtime.create_vault(('telegram', '7'), target())
        monkeypatch.setattr('secure_env_ingress.runtime.time.monotonic', lambda: links['expires_at'] + 1)
        with pytest.raises(Exception):
            runtime.submit(token(links), '', ['name', 'password'])
        assert links['completion'].result(timeout=1)['status'] == 'expired'
        assert not (home / 'vault' / 'vault.json.enc').exists()
    finally:
        runtime.close()


def test_expiry_wakes_waiter_and_disallows_late_submit(tmp_path, monkeypatch):
    runtime, config, home, root = setup(tmp_path, monkeypatch)
    try:
        links = runtime.create_vault(('telegram', '7'), target())
        # Expire the exact pair in memory; no wall-clock waiting or polling.
        runtime._store.clear()
        with runtime._lock:
            runtime._stop_listener()
        assert links['completion'].result() == {'status': 'expired'}
        with pytest.raises(Exception):
            runtime.submit(token(links), '', ['name', 'pass'])
    finally:
        runtime.close()
