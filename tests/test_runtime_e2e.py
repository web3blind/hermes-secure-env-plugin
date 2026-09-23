"""Real local HTTPS → capability → durable temporary dotenv integration."""
import hashlib
import hmac
import http.client
import json
import os
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit
import pytest
from dotenv import dotenv_values
from test_tls import cert_material
from secure_env_ingress.runtime import IngressRuntime


def make_runtime(tmp_path, mini=True):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    cert, key, root = cert_material(tmp_path / 'certs')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    config = {
        'public_ip': '127.0.0.1', 'listen_host': '127.0.0.1', 'listen_port': port,
        'cert_path': str(cert), 'key_path': str(key), 'ttl_seconds': 120,
        'safety_seconds': 3600, 'allowed_telegram_user_ids': [7],
        'mini_app_enabled': mini,
        'profiles': {'service': {'target_mode': 'hermes', 'keys': ['SERVICE_TOKEN']}},
    }
    runtime = IngressRuntime(config, home, '111:fixture-only', trust_roots=root)
    return runtime, config, home, root


def signed_data(uid=7):
    fields = {'auth_date': str(int(time.time())), 'user': json.dumps({'id': uid})}
    check = '\n'.join(f'{k}={v}' for k, v in sorted(fields.items()))
    secret = hmac.new(b'WebAppData', b'111:fixture-only', hashlib.sha256).digest()
    fields['hash'] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(fields)


def post(config, root, path, body):
    conn = http.client.HTTPSConnection('127.0.0.1', config['listen_port'], context=ssl.create_default_context(cafile=str(root)), timeout=3)
    try:
        conn.request('POST', path, json.dumps(body), headers={'Content-Type': 'application/json', 'Origin': f"https://127.0.0.1:{config['listen_port']}"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


@pytest.mark.parametrize('mini', [False, True])
def test_real_https_write_mode_binding_replay_shutdown(tmp_path, caplog, mini):
    runtime, config, home, root = make_runtime(tmp_path)
    try:
        urls = runtime.create(7, 'service')
        token = urlsplit(urls['web_app_url'] if mini else urls['url']).fragment
        init = signed_data() if mini else ''
        if mini:
            status, _ = post(config, root, '/session', {'token': token, 'initData': ''})
            assert status == 403
        status, data = post(config, root, '/session', {'token': token, 'initData': init})
        assert status == 200 and data['keys'] == ['SERVICE_TOKEN']
        assert not (home / '.env').exists()
        value = 'fixture-' + os.urandom(12).hex()
        status, data = post(config, root, '/submit', {'token': token, 'initData': init, 'values': [value]})
        assert status == 200 and data == {'added': ['SERVICE_TOKEN']}
        stored = dotenv_values(home / '.env', interpolate=False)['SERVICE_TOKEN']
        assert stored is not None
        assert hashlib.sha256(stored.encode()).digest() == hashlib.sha256(value.encode()).digest()
        assert (home / '.env').stat().st_mode & 0o777 == 0o600
        with pytest.raises(Exception):
            runtime.submit(token, init, [value])
        assert value not in caplog.text and token not in caplog.text
        deadline = time.monotonic() + 3
        while runtime._server is not None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert runtime._server is None
    finally:
        runtime.close()


def test_cancel_and_second_request_invalidate_old_capability(tmp_path):
    runtime, config, home, root = make_runtime(tmp_path)
    try:
        old = urlsplit(runtime.create(7, 'service')['url']).fragment
        new = urlsplit(runtime.create(7, 'service')['url']).fragment
        with pytest.raises(Exception):
            runtime.session(old, '')
        runtime.cancel(7)
        with pytest.raises(Exception):
            runtime.session(new, '')
        assert not (home / '.env').exists()
        assert runtime._server is None
    finally:
        runtime.close()


def test_startup_and_preflight_have_no_listener_or_state(tmp_path):
    runtime, config, home, root = make_runtime(tmp_path)
    try:
        runtime.preflight()
        assert runtime._server is None
        assert not (home / 'secrets-ingress').exists()
        with pytest.raises(Exception):
            runtime.create(99, 'service')
        assert runtime._server is None
    finally:
        runtime.close()
