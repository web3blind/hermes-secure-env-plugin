"""Multiplex gateway routing into independently owned disposable secret homes."""
import asyncio
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from dotenv import dotenv_values
from gateway.config import GatewayConfig, Platform
from gateway.platforms.event import MessageEvent
from gateway.session import SessionSource
from secure_env_ingress.plugin import SAFE_ERROR
from generic_helpers import registered
from test_runtime_e2e import make_runtime, post


@pytest.mark.asyncio
async def test_primary_adapter_routes_two_profile_owners_to_independent_https_targets(tmp_path, monkeypatch):
    user_home = tmp_path / 'user'
    primary = user_home / '.hermes'
    primary.mkdir(parents=True)
    monkeypatch.setattr(Path, 'home', lambda: user_home)
    monkeypatch.setenv('HOME', str(user_home))
    monkeypatch.setenv('HERMES_HOME', str(primary))
    monkeypatch.delenv('HERMES_PROFILE', raising=False)
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,99')
    monkeypatch.setenv('GATEWAY_ALLOW_ALL_USERS', 'false')

    fixtures = []
    for name, owner, key in (('alpha', 88, 'ALPHA_FIXTURE'), ('beta', 99, 'BETA_FIXTURE')):
        base = tmp_path / name
        base.mkdir()
        sample, settings, _unused_home, root = make_runtime(base)
        sample.close()
        home = primary / 'profiles' / name
        home.mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        settings.update(allowed_telegram_user_ids=[owner], mini_app_enabled=False,
                        profiles={'service': {'target_mode': 'hermes', 'keys': [key]}})
        fixtures.append((name, owner, key, settings, home, root))

    from gateway.profile_routing import parse_profile_routes
    routes = parse_profile_routes([
        {'name': name, 'platform': 'telegram', 'chat_id': f'room-{name}', 'profile': name}
        for name, *_rest in fixtures
    ])
    with registered(monkeypatch, fixtures[0][4], settings=fixtures[0][3], trust_roots=fixtures[0][5]) as (alpha, runner):
        with registered(monkeypatch, fixtures[1][4], settings=fixtures[1][3], trust_roots=fixtures[1][5]) as (beta, _):
            runner.config = GatewayConfig(multiplex_profiles=True, profile_routes=routes)
            runner._primary_profile_name = 'default'
            runner._profile_adapters = {name: {Platform.TELEGRAM: runner.adapters[Platform.TELEGRAM]}
                                        for name, *_ in fixtures}
            handler = runner._make_default_profile_message_handler()

            def event(uid, chat_id):
                return MessageEvent(
                    source=SessionSource(platform=Platform.TELEGRAM, user_id=str(uid),
                                         chat_id=chat_id, chat_type='group'),
                    text='/senv service')

            for name, owner, key, settings, home, root in fixtures:
                message = event(owner, f'room-{name}')
                reply = await handler(message)
                assert 'One-time form sent' in reply and 'https://' not in reply
                assert runner.sent[-1][:2] == (Platform.TELEGRAM, f'room-{name}')
                assert message.source.profile == name
                try:
                    from gateway.session_identity import identity_of
                except ImportError:  # Older live hosts route via source.profile and scoped home.
                    pass
                else:
                    identity = identity_of(message.source)
                    assert identity is not None
                    assert identity.authorization_home == primary
                    assert identity.runtime_home == home
                assert not (home / '.env').exists()
                delivered = runner.sent[-1][2]
                token = urlsplit('https://' + delivered.split('https://', 1)[1].split()[0]).fragment
                status, result = await asyncio.to_thread(
                    post, settings, root, '/submit',
                    {'token': token, 'initData': '', 'values': [name + '-secret']})
                assert (status, result) == (200, {'added': [key]})
                assert dotenv_values(home / '.env', interpolate=False) == {key: name + '-secret'}

            before = [(home / '.env').read_bytes() for _, _, _, _, home, _ in fixtures]
            # Primary transport allows both senders, but the routed beta manager does not own 88.
            mismatch = event(88, 'room-beta')
            denied = await handler(mismatch)
            assert mismatch.source.profile == 'beta'
            assert denied == SAFE_ERROR
            outsider = event(77, 'room-alpha')
            assert await handler(outsider) is None
            assert [(home / '.env').read_bytes() for _, _, _, _, home, _ in fixtures] == before
            assert not (primary / '.env').exists()
