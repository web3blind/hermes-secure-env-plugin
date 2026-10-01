"""Synthetic payment HTTPS storage; no real card or production Vault."""
import json
from urllib.parse import urlsplit

import pytest

from test_runtime_e2e import make_runtime, post
from secure_env_ingress.vault_ingress import capture_login_target
from secure_env_ingress.server import HTTPError

# Stripe-documented test card; expiry is generated to keep the fixture usable.
def card_values():
    import datetime
    return ['4242424242424242', 'Synthetic Holder', '12', str(datetime.datetime.now(datetime.timezone.utc).year + 2), '123', '12345']


@pytest.mark.parametrize('choice,expected', [('once', True), ('deny', False), ('unresolved', False), ('missing', False)])
def test_native_payment_consent_real_gateway_boundary(choice, expected):
    from tools.browser_vault_tool import _confirm_payment_fill
    from payment_consent_helpers import payment_consent
    with payment_consent(choice) as seen:
        assert _confirm_payment_fill('Synthetic card', 'https://site.test') is expected
    assert len(seen) == (0 if choice == 'missing' else 1)
    if seen:
        assert 'Synthetic card' in seen[0]['command'] and 'https://site.test' in seen[0]['command']
        assert card_values()[0] not in json.dumps(seen)


def issue(runtime):
    return runtime.create_vault(('telegram', '7'),
        capture_login_target('https://site.test', 'Synthetic card', 'task', 'key'), mode='payment')


def test_payment_https_append_native_encryption(tmp_path, monkeypatch, caplog):
    from agent.vault_store import VaultStore
    from tools import browser_vault_tool
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr(browser_vault_tool, '_confirm_payment_fill', lambda *a: pytest.fail('storage must not request fill consent'))
    try:
        for _ in range(2):
            links = issue(runtime)
            token = urlsplit(links['url']).fragment
            status, info = post(cfg, root, '/session', {'token': token, 'initData': ''})
            assert status == 200 and info['kind'] == 'browser_payment'
            assert len(info['keys']) == 6
            values = card_values()
            status, result = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': values})
            assert (status, result) == (200, {'saved': True})
            outcome = links['completion'].result(2)
            assert outcome['status'] == 'saved' and outcome['origin'] == 'https://site.test'
            store = VaultStore(home / 'vault')
            meta = store.get_meta(outcome['handle'])
            assert meta.kind == 'payment' and meta.origin == 'https://site.test'
            assert meta.identifier is None
            assert store.resolve_secret(meta.id) == dict(zip(
                ['card_number', 'cardholder_name', 'exp_month', 'exp_year', 'cvc', 'billing_postal_code'], values))
            native = browser_vault_tool.browser_vault_list()
            assert values[0] not in native and values[0] not in json.dumps(outcome) and values[0] not in caplog.text
            assert values[0].encode() not in (home / 'vault' / 'vault.json.enc').read_bytes()
            with pytest.raises(HTTPError):
                runtime.submit(token, '', values)
        assert len(store.list_items()) == 2
        assert not (home / '.env').exists()
    finally:
        runtime.close()


@pytest.mark.parametrize('index,bad', [(0,'4242424242424241'), (0,'4242 4242 4242 4242'),
    (0,'４２４２４２４２４２４２４２４２'), (0,'1'*20), (1,'bad\nname'), (2,'00'), (2,'13'),
    (2,'1.5'), (3,'2020'), (3,'99'), (4,'12'), (4,'12345'), (4,'abc'), (5,'x'*33)])
def test_payment_invalid_terminal_no_write(tmp_path, monkeypatch, index, bad):
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    try:
        links = issue(runtime)
        token = urlsplit(links['url']).fragment
        values = card_values()
        values[index] = bad
        status, body = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': values})
        assert status == 400 and body['error'] in ('invalid_payment_values', 'invalid_request')
        assert links['completion'].result(2)['status'] == 'rejected'
        assert not (home / 'vault' / 'vault.json.enc').exists()
        with pytest.raises(HTTPError):
            runtime.submit(token, '', card_values())
    finally:
        runtime.close()


def test_payment_optional_fields_and_four_digit_cvc():
    from secure_env_ingress.payment import payment_secret
    values = card_values()
    values[0] = '378282246310005'  # documented synthetic Amex card
    values[1] = values[5] = ''
    values[2] = '01'
    values[4] = '0123'
    secret = payment_secret(values)
    assert set(secret) == {'card_number', 'exp_month', 'exp_year', 'cvc'}
    assert secret['cvc'] == '0123' and secret['exp_month'] == '01'


@pytest.mark.parametrize('field', ['kind', 'origin'])
def test_payment_native_metadata_mismatch_is_unknown(tmp_path, monkeypatch, field):
    from dataclasses import replace
    from agent.vault_store import VaultStore
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    original = VaultStore.add_item
    def write_then_wrong_meta(self, *args, **kwargs):
        meta = original(self, *args, **kwargs)
        return replace(meta, **{field: 'login' if field == 'kind' else 'https://wrong.test'})
    monkeypatch.setattr(VaultStore, 'add_item', write_then_wrong_meta)
    try:
        links = issue(runtime)
        token = urlsplit(links['url']).fragment
        status, result = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': card_values()})
        assert (status, result) == (409, {'error': 'write_failed'})
        assert links['completion'].result(2)['status'] == 'unknown'
        assert len(VaultStore(home / 'vault').list_items()) == 1
        with pytest.raises(HTTPError):
            runtime.submit(token, '', card_values())
    finally:
        runtime.close()


@pytest.mark.parametrize('mutation', ['permissions', 'directory_replaced'])
def test_payment_rejects_changed_vault_binding(tmp_path, monkeypatch, mutation):
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    vault = home / 'vault'
    vault.mkdir(mode=0o700)
    try:
        links = issue(runtime)
        if mutation == 'permissions':
            vault.chmod(0o777)
        else:
            vault.rename(home / 'old-vault')
            vault.mkdir(mode=0o700)
        token = urlsplit(links['url']).fragment
        status, result = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': card_values()})
        assert (status, result) == (409, {'error': 'write_failed'})
        assert links['completion'].result(2)['status'] == 'failed'
        assert not (vault / 'vault.json.enc').exists()
    finally:
        vault.chmod(0o700)
        runtime.close()


@pytest.mark.parametrize('origin', ['http://site.test', 'https://site.test/', 'https://site.test/path', 'https://site.test:443', 'https://user@site.test', 'https://site.test?x=1'])
def test_payment_requires_exact_https_origin(origin):
    with pytest.raises(ValueError):
        capture_login_target(origin, 'Synthetic card', 'task', 'key')


@pytest.mark.parametrize('terminal', ['cancelled', 'superseded', 'expired'])
def test_payment_capability_lifecycle(tmp_path, monkeypatch, terminal):
    runtime, _, home, _ = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    try:
        links = issue(runtime)
        token = urlsplit(links['url']).fragment
        if terminal == 'cancelled':
            runtime.cancel_group(links['group_id'])
        elif terminal == 'superseded':
            issue(runtime)
        else:
            runtime._store._clock = lambda: links['expires_at'] + 1
            with runtime._lock:
                runtime._stop_listener()
        assert links['completion'].result(2)['status'] == terminal
        with pytest.raises(HTTPError):
            runtime.submit(token, '', card_values())
        assert not (home / 'vault' / 'vault.json.enc').exists()
    finally:
        runtime.close()
