"""Synthetic encrypted target proves registered tool → HTTPS → trusted consumer."""
import asyncio
import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from cryptography.fernet import Fernet

from generic_helpers import registered
from test_runtime_e2e import make_runtime, post
from test_tool_https_e2e import running_gateway_loop
from secure_env_ingress.operations import BoundOperation, bind, register_consumer
from secure_env_ingress.runtime import OperationTarget
from secure_env_ingress.server import HTTPError


def consumer(home, ciphertext, output):
    def factory(raw):
        data = json.loads(raw)
        if set(data) != {'target'} or data['target'] != 'fixture':
            raise ValueError('invalid target')
        frozen = bytes(ciphertext)
        def execute(secret):
            key = hashlib.pbkdf2_hmac('sha256', secret.encode(), b'fixture-salt', 1000, dklen=32)
            import base64
            plaintext = Fernet(base64.urlsafe_b64encode(key)).decrypt(frozen)
            output.append(hashlib.sha256(plaintext + b':acted').hexdigest())
        return BoundOperation('Unlock fixture and record action digest, target fixture', execute)
    register_consumer(home, 'fixture_action', factory)


def target(home, name='fixture_action', params=None):
    op, canonical = bind(home, name, {'target': 'fixture'} if params is None else params)
    digest = hashlib.sha256(name.encode() + canonical + b'owner7:session:chat').digest()
    return OperationTarget(name, op.summary, op.execute, (int.from_bytes(digest, 'big'), 0),
                           'session', '-600', '99')


def configured_fixture(home, settings, ciphertext):
    """Create independently installed consumer code, not a manual registration."""
    import textwrap
    source = textwrap.dedent(f'''\
        import base64
        import hashlib
        import json
        from cryptography.fernet import Fernet
        from secure_env_ingress.operations import BoundOperation

        CIPHERTEXT = {ciphertext!r}
        OUTPUT = {str(home / 'action_digest')!r}

        def factory(raw):
            data = json.loads(raw)
            if set(data) != {{'target'}} or data['target'] != 'fixture':
                raise ValueError('invalid target')
            frozen = bytes(CIPHERTEXT)
            def execute(secret):
                key = hashlib.pbkdf2_hmac('sha256', secret.encode(), b'fixture-salt', 1000, dklen=32)
                plaintext = Fernet(base64.urlsafe_b64encode(key)).decrypt(frozen)
                with open(OUTPUT, 'w', encoding='ascii') as output:
                    output.write(hashlib.sha256(plaintext + b':acted').hexdigest())
            return BoundOperation('Unlock fixture and record action digest, target fixture', execute)
    ''')
    module = home / 'external_action.py'
    module.write_text(source, encoding='utf-8')
    module.chmod(0o600)
    settings = dict(settings)
    settings['consumers'] = {'fixture_action': {
        'path': str(module), 'factory': 'factory',
        'sha256': hashlib.sha256(module.read_bytes()).hexdigest()}}
    return settings


@pytest.mark.parametrize('bad_first', [False, True])
def test_registered_dispatch_https_encrypted_action(tmp_path, monkeypatch, bad_first):
    from gateway import session_context as sc
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.run import GatewayRunner, _profile_runtime_scope
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from secure_env_ingress import runtime as runtime_module
    from tools.registry import registry
    import base64

    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    secret = 'synthetic-passphrase'
    key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', secret.encode(), b'fixture-salt', 1000, dklen=32))
    ciphertext = Fernet(key).encrypt(b'synthetic-payload')
    settings = configured_fixture(home, settings, ciphertext)
    bad_module = home / 'bad_action.py'
    bad_module.write_text("raise RuntimeError('synthetic-private-error')")
    bad_module.chmod(0o600)
    bad = {'path': str(bad_module), 'factory': 'factory', 'sha256': '0' * 64}
    good = settings['consumers']['fixture_action']
    pairs = [('fixture_action', good), ('bad_action', bad)]
    settings['consumers'] = dict(reversed(pairs) if bad_first else pairs)
    # The HTTPS runtime accepts only ingress settings, not plugin-only allowlist.
    https_settings = {k: v for k, v in settings.items() if k != 'consumers'}
    original = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime',
        lambda cfg, selected_home, bot: original(cfg, selected_home, bot, trust_roots=root))

    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            assert chat_id == '-600' and metadata == {'thread_id': '99'}
            assert secret not in content and 'fixture_action' in content
            token = urlsplit(content.split('bearer link): ', 1)[1].split(' Operation:', 1)[0]).fragment
            status, form = await asyncio.to_thread(post, https_settings, root, '/session', {'token': token, 'initData': ''})
            assert status == 200 and form['summary'] == 'Unlock fixture and record action digest, target fixture'
            status, body = await asyncio.to_thread(post, https_settings, root, '/submit',
                {'token': token, 'initData': '', 'values': [secret]})
            assert (status, body) == (200, {'completed': True})
            status, _ = await asyncio.to_thread(post, https_settings, root, '/submit',
                {'token': token, 'initData': '', 'values': [secret]})
            assert status == 410
            return SimpleNamespace(success=True)

    gateway = object.__new__(GatewayRunner)
    gateway.adapters = {Platform.TELEGRAM: Adapter()}
    gateway._profile_adapters = {}
    gateway._primary_profile_name = 'default'
    gateway.config = SimpleNamespace()
    with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings):
        gateway._gateway_loop = loop
        with _profile_runtime_scope(home, {}):
            invoke_hook('pre_gateway_dispatch', event=MessageEvent(source=SessionSource(
                platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'),
                text='ordinary message'), gateway=gateway)
            tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
                chat_type='forum', thread_id='99', session_id='sid', session_key='key',
                profile='', cron_session='')
            try:
                raw = registry.dispatch('secure_operation',
                    {'operation': 'fixture_action', 'parameters': {'target': 'fixture'}},
                    task_id='sid', session_id='sid')
                assert json.loads(registry.dispatch('secure_operation',
                    {'operation': 'bad_action', 'parameters': {}}, task_id='sid', session_id='sid')) == {
                        'success': False, 'status': 'consumer_binding'}
            finally:
                sc.clear_session_vars(tokens)
    assert json.loads(raw) == {'success': True, 'status': 'completed'}
    assert (home / 'action_digest').read_text() == hashlib.sha256(b'synthetic-payload:acted').hexdigest()
    assert secret not in raw and not (home / '.env').exists() and not (home / 'vault').exists()


@pytest.mark.parametrize('fault', ['hash', 'path', 'shape', 'missing_factory',
                                   'duplicate', 'writable', 'null', 'verified'])
def test_configured_consumer_startup_fail_closed(tmp_path, monkeypatch, fault):
    from secure_env_ingress.operations import clear_consumers
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    settings = configured_fixture(home, settings, b'fixture')
    item = settings['consumers']['fixture_action']
    if fault == 'hash':
        item['sha256'] = '0' * 64
    elif fault == 'path':
        item['path'] = str(home / 'missing.py')
    elif fault == 'shape':
        item['shell'] = 'do-not-execute'
    elif fault == 'missing_factory':
        item['factory'] = 'not_defined'
    elif fault == 'duplicate':
        register_consumer(home, 'fixture_action', lambda _: BoundOperation('Manual', lambda _: None))
    elif fault == 'writable':
        (home / 'external_action.py').chmod(0o666)
    elif fault == 'null':
        settings['consumers'] = None
    elif fault == 'verified':
        item['requires_verified_principal'] = True
    try:
        with registered(monkeypatch, home, settings=settings) as (manager, _):
            from tools.registry import registry
            assert 'senv' in manager._plugin_commands
            assert all(registry.get_entry(name, scope=str(home)) for name in (
                'browser_vault', 'secure_payment_fill', 'secure_operation'))
            with pytest.raises(ValueError):
                bind(home, 'fixture_action', {'target': 'fixture'})
            assert not (home / 'secrets-ingress').exists()
    finally:
        clear_consumers(home)


def test_configured_consumer_profile_isolation_and_manual_coexistence(tmp_path, monkeypatch):
    from secure_env_ingress.operations import clear_consumers
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    settings = configured_fixture(home, settings, b'fixture')
    register_consumer(home, 'manual', lambda _: BoundOperation('Manual action', lambda _: None))
    try:
        with registered(monkeypatch, home, settings=settings):
            assert bind(home, 'fixture_action', {'target': 'fixture'})[0].summary.startswith('Unlock fixture')
            assert bind(home, 'manual', {})[0].summary == 'Manual action'
            with pytest.raises(ValueError):
                bind(tmp_path / 'another-profile', 'fixture_action', {'target': 'fixture'})
        with pytest.raises(ValueError):
            bind(home, 'fixture_action', {'target': 'fixture'})
    finally:
        clear_consumers(home)


def test_tool_deadline_returns_unknown_while_callback_still_running(tmp_path, monkeypatch):
    from gateway import session_context as sc
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.run import GatewayRunner, _profile_runtime_scope
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from secure_env_ingress import runtime as runtime_module
    from tools.registry import registry

    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    entered, release = threading.Event(), threading.Event()
    actions = []
    register_consumer(home, 'blocking_tool', lambda _: BoundOperation('Fixed action',
        lambda secret: (entered.set(), release.wait(10), actions.append('acted'))))
    real = runtime_module.IngressRuntime

    class ShortDeadline(real):
        def create_operation(self, owner, target):
            links = super().create_operation(owner, target)
            return {**links, 'expires_at': time.monotonic() + 0.5}

    monkeypatch.setattr(runtime_module, 'IngressRuntime',
                        lambda cfg, selected_home, bot: ShortDeadline(cfg, selected_home, bot, trust_roots=root))
    with ThreadPoolExecutor(max_workers=1) as pool:
        posted = []
        class Adapter:
            async def send(self, chat_id, content, metadata=None):
                token = urlsplit(content.split('bearer link): ', 1)[1].split(' Operation:', 1)[0]).fragment
                posted.append(pool.submit(post, settings, root, '/submit',
                    {'token': token, 'initData': '', 'values': ['synthetic']}))
                assert await asyncio.to_thread(entered.wait, 2)
                return SimpleNamespace(success=True)

        gateway = object.__new__(GatewayRunner)
        gateway.adapters = {Platform.TELEGRAM: Adapter()}
        gateway._profile_adapters = {}
        gateway._primary_profile_name = 'default'
        gateway.config = SimpleNamespace()
        try:
            with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings):
                gateway._gateway_loop = loop
                with _profile_runtime_scope(home, {}):
                    invoke_hook('pre_gateway_dispatch', event=MessageEvent(source=SessionSource(
                        platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'),
                        text='ordinary message'), gateway=gateway)
                    tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
                        chat_type='forum', thread_id='99', session_id='sid', session_key='key',
                        profile='', cron_session='')
                    try:
                        start = time.monotonic()
                        raw = registry.dispatch('secure_operation',
                            {'operation': 'blocking_tool', 'parameters': {'target': 'fixture'}},
                            task_id='sid', session_id='sid')
                    finally:
                        sc.clear_session_vars(tokens)
            assert json.loads(raw) == {'success': False, 'status': 'unknown'}
            assert time.monotonic() - start < 3
            assert posted and not posted[0].done()
        finally:
            release.set()
        assert posted[0].result(timeout=3) == (409, {'error': 'operation_unconfirmed'})
    assert actions == ['acted']


def test_context_rejection_and_consumers(tmp_path):
    home = tmp_path / 'home'
    other = tmp_path / 'other'
    register_consumer(home, 'verified', lambda _: BoundOperation('summary', lambda _: None),
                      requires_verified_principal=True)
    with pytest.raises(ValueError):
        bind(home, 'verified', {})
    with pytest.raises(ValueError):
        bind(other, 'verified', {})
    with pytest.raises(ValueError):
        bind(home, 'unknown', {})
    register_consumer(home, 'bounded', lambda _: BoundOperation('summary', lambda _: None))
    with pytest.raises(ValueError):
        bind(home, 'bounded', {'x': 'a' * 4096})
    with pytest.raises(ValueError):
        bind(home, 'bounded', {'x': float('nan')})
    with pytest.raises(ValueError):
        register_consumer(home, 'bounded', lambda _: None)


def test_lifecycle_tamper_rejection_unknown_and_no_echo(tmp_path):
    runtime, settings, home, root = make_runtime(tmp_path, mini=False)
    seen = []
    register_consumer(home, 'failing', lambda _: BoundOperation('Fixed target',
        lambda secret: (_ for _ in ()).throw(RuntimeError(secret))))
    register_consumer(home, 'other', lambda _: BoundOperation('Other target', lambda secret: seen.append(secret)))
    try:
        t = target(home, 'failing')
        links = runtime.create_operation(('telegram', '7'), t)
        token = urlsplit(links['url']).fragment
        claim = runtime._store.peek(token)
        assert claim is not None
        assert claim.user_id == '7' and claim.hermes_home == home.absolute()
        assert claim.target_id == t.identity and claim.profile_name == 'default'
        assert runtime.session(token, '')['summary'] == 'Fixed target'
        runtime._targets[claim.group_id] = target(home, 'other')
        status, _ = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['SECRET-ECHO']})
        assert status == 410 and seen == []
        runtime._targets[claim.group_id] = t
        status, _ = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['SECRET-ECHO']})
        assert status == 410  # tampered request is terminal via server rejection
        links = runtime.create_operation(('telegram', '7'), t)
        token = urlsplit(links['url']).fragment
        status, body = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['SECRET-ECHO']})
        assert status == 409 and body == {'error': 'operation_unconfirmed'}
        assert links['completion'].result(timeout=1) == {'status': 'unknown'}
        assert 'SECRET-ECHO' not in json.dumps(body)
        old = runtime.create_operation(('telegram', '7'), t)
        new = runtime.create_operation(('telegram', '7'), t)
        assert old['completion'].result(timeout=1) == {'status': 'superseded'}
        assert post(settings, root, '/session', {'token': urlsplit(old['url']).fragment, 'initData': ''})[0] == 410
        runtime.cancel(('telegram', '7'))
        assert new['completion'].result(timeout=1) == {'status': 'cancelled'}
        expiry = runtime.create_operation(('telegram', '7'), t)
        expiry_token = urlsplit(expiry['url']).fragment
        runtime._store._clock = lambda: expiry['expires_at'] + 1
        assert runtime._store.peek(expiry_token) is None
    finally:
        runtime.close()


def test_operation_value_bounds_return_suppression_and_mini_denial(tmp_path):
    runtime, settings, home, root = make_runtime(tmp_path, mini=True)
    register_consumer(home, 'echo', lambda _: BoundOperation('Fixed public action',
        lambda secret: secret))
    try:
        t = target(home, 'echo')
        links = runtime.create_operation(('telegram', '7'), t)
        token = urlsplit(links['url']).fragment
        claim = runtime._store.peek(token)
        assert claim is not None and claim.expires_at - claim.created_at <= 240
        assert runtime._operation_groups == {claim.group_id}
        assert 'web_app_url' not in links
        status, body = post(settings, root, '/submit',
            {'token': token, 'initData': '', 'values': ['x' * 4097]})
        assert status == 400 and body == {'error': 'invalid_values'}
        assert links['completion'].result(timeout=1) == {'status': 'rejected'}
        links = runtime.create_operation(('telegram', '7'), t)
        token = urlsplit(links['url']).fragment
        status, body = post(settings, root, '/submit',
            {'token': token, 'initData': '', 'values': ['ECHO-NOT-RETURNED']})
        assert (status, body) == (200, {'completed': True})
        assert links['completion'].result(timeout=1) == {'status': 'completed'}
        assert 'ECHO-NOT-RETURNED' not in json.dumps(body)
        assert not (home / '.env').exists()
    finally:
        runtime.close()


def test_slow_successful_operation_survives_consumed_link_monitor(tmp_path):
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    actions = []
    def execute(secret):
        time.sleep(0.8)  # Cross several expiry-monitor ticks, well before the real deadline.
        actions.append('acted')
    register_consumer(home, 'slow_success', lambda _: BoundOperation('Fixed slow action', execute))
    try:
        links = runtime.create_operation(('telegram', '7'), target(home, 'slow_success'))
        status, body = post(cfg, root, '/submit', {
            'token': urlsplit(links['url']).fragment, 'initData': '', 'values': ['synthetic']})
        assert (status, body) == (200, {'completed': True})
        assert links['completion'].result(timeout=1) == {'status': 'completed'}
        assert actions == ['acted']
    finally:
        runtime.close()


@pytest.mark.parametrize('ending', ['cancel_group', 'cancel_owner', 'deadline', 'close'])
def test_blocked_operation_resolves_unknown_without_waiting_for_callback(tmp_path, ending):
    case = tmp_path / ending
    case.mkdir()
    runtime, _, home, _ = make_runtime(case, mini=False)
    entered, release = threading.Event(), threading.Event()
    actions = []
    register_consumer(home, 'blocking', lambda _: BoundOperation('Fixed action',
        lambda secret: (entered.set(), release.wait(10), actions.append('acted'))))
    links = runtime.create_operation(('telegram', '7'), target(home, 'blocking'))
    token = urlsplit(links['url']).fragment
    with ThreadPoolExecutor(max_workers=1) as pool:
        worker = pool.submit(runtime.submit, token, '', ['synthetic'])
        try:
            assert entered.wait(2)
            start = time.monotonic()
            if ending == 'cancel_group':
                runtime.cancel_group(links['group_id'])
            elif ending == 'cancel_owner':
                runtime.cancel(('telegram', '7'))
            elif ending == 'deadline':
                runtime._store._clock = lambda: links['expires_at'] + 1
            else:
                runtime.close()
            assert links['completion'].result(timeout=2) == {'status': 'unknown'}
            assert time.monotonic() - start < 2
            assert not worker.done()
            if ending != 'close':
                with pytest.raises(HTTPError) as error:
                    runtime.create_operation(('telegram', '7'), target(home, 'blocking'))
                assert error.value.code == 'operation_busy'
        finally:
            release.set()
            with pytest.raises(HTTPError, match='operation_unconfirmed'):
                worker.result(timeout=3)
            runtime.close()
    assert actions == ['acted']  # Unknown does not imply the action stopped.
    assert links['completion'].result() == {'status': 'unknown'}


def test_late_callback_does_not_touch_new_group(tmp_path):
    runtime, _, home, _ = make_runtime(tmp_path, mini=False)
    entered, release = threading.Event(), threading.Event()
    actions = []
    register_consumer(home, 'blocking', lambda _: BoundOperation('Fixed action',
        lambda secret: (entered.set(), release.wait(10), actions.append('old'))))
    register_consumer(home, 'quick', lambda _: BoundOperation('Other fixed action',
        lambda secret: actions.append('new')))
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = runtime.create_operation(('telegram', '7'), target(home, 'blocking'))
        worker = pool.submit(runtime.submit, urlsplit(first['url']).fragment, '', ['synthetic'])
        try:
            assert entered.wait(2)
            runtime.cancel_group(first['group_id'])
            assert first['completion'].result(timeout=1) == {'status': 'unknown'}
        finally:
            release.set()
            with pytest.raises(HTTPError, match='operation_unconfirmed'):
                worker.result(timeout=3)
        second = runtime.create_operation(('telegram', '7'), target(home, 'quick'))
        assert runtime.submit(urlsplit(second['url']).fragment, '', ['synthetic']) == {'completed': True}
        assert second['completion'].result(timeout=1) == {'status': 'completed'}
        assert first['completion'].result() == {'status': 'unknown'}
        runtime.close()
    assert actions == ['old', 'new']


def test_operation_callback_receives_bound_profile_context(tmp_path, monkeypatch):
    from hermes_constants import get_hermes_home, set_hermes_home_override, reset_hermes_home_override
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    default = tmp_path / '.hermes'
    default.mkdir()
    home = default / 'profiles' / 'named'
    home.mkdir(parents=True)
    monkeypatch.setenv('HERMES_HOME', str(default))
    (tmp_path / 'fixture').mkdir()
    sample, settings, _, root = make_runtime(tmp_path / 'fixture', mini=False)
    sample.close()
    from secure_env_ingress.runtime import IngressRuntime
    runtime = IngressRuntime(settings, home, '111:fixture-only', trust_roots=root)
    seen = []
    register_consumer(home, 'profile_action', lambda _: BoundOperation('Profile action',
        lambda secret: seen.append((get_hermes_home(), secret))))
    scope = set_hermes_home_override(home)
    try:
        links = runtime.create_operation(('telegram', '7'), target(home, 'profile_action'))
    finally:
        reset_hermes_home_override(scope)
    try:
        assert get_hermes_home() == default
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(runtime.submit, urlsplit(links['url']).fragment, '', ['synthetic']).result(timeout=3) == {'completed': True}
        assert seen == [(home, 'synthetic')]
    finally:
        runtime.close()


@pytest.mark.parametrize('wrong', ['owner', 'profile', 'task', 'arguments'])
def test_registered_tool_rejects_unbound_request(tmp_path, monkeypatch, wrong):
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry

    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    consumer(home, b'ciphertext-fixture', [])
    with registered(monkeypatch, home, settings=settings, trust_roots=root):
        with _profile_runtime_scope(home, {}):
            vars = sc.set_session_vars(platform='telegram', user_id='8' if wrong == 'owner' else '7',
                chat_id='-600', chat_type='group', session_id='sid', session_key='key',
                profile='different' if wrong == 'profile' else '', cron_session='')
            try:
                payload = {'operation': 'fixture_action', 'parameters': {'target': 'fixture'}}
                if wrong == 'arguments':
                    payload['password'] = 'FORBIDDEN'
                result = json.loads(registry.dispatch('secure_operation', payload,
                    task_id='wrong' if wrong == 'task' else 'sid', session_id='sid'))
            finally:
                sc.clear_session_vars(vars)
        assert result == {'success': False, 'status': 'session_binding'}
        assert not (home / 'secrets-ingress').exists()
