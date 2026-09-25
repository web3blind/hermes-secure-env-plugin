"""Real gateway admission + profile manager + HTTPS writer, with disposable homes only."""
import asyncio
import inspect
from urllib.parse import urlsplit

import pytest
from dotenv import dotenv_values
from gateway.config import Platform
from gateway.platforms.event import MessageEvent
from gateway.session import SessionSource
import hermes_cli.lifecycle as lifecycle
from secure_env_ingress.plugin import SAFE_ERROR
from generic_helpers import dispatch, registered
from test_runtime_e2e import make_runtime, post


def token_from_message(reply):
    assert reply.count('https://') == 1
    return urlsplit('https://' + reply.split('https://', 1)[1].split()[0]).fragment


def token_from(runner):
    assert runner.sent
    return token_from_message(runner.sent[-1][2])


@pytest.mark.asyncio
async def test_host_and_plugin_denials_are_independent_and_inert(tmp_path, monkeypatch):
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings.update(allowed_telegram_user_ids=[88, 99], allowed_owners={'discord': ['opaque-user:A']},
                    mini_app_enabled=False)
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,89')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', '88,opaque-user:A')
    monkeypatch.setenv('GATEWAY_ALLOW_ALL_USERS', 'false')
    with registered(monkeypatch, home, settings=settings, trust_roots=root) as (manager, runner):
        # Lifecycle composition is public API, not direct invocation of the callback.
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='99',
                            chat_id='trusted', chat_type='group'), text='/senv service')
        lifecycle_hook = getattr(lifecycle, 'ainvoke_hook', lifecycle.invoke_hook)
        observed = lifecycle_hook('pre_gateway_dispatch', event=event, gateway=runner)
        assert (await observed if inspect.isawaitable(observed) else observed) == []
        assert await dispatch(manager, runner, '/senv service', uid='99') is None  # plugin grants, host rejects
        assert SAFE_ERROR == await dispatch(manager, runner, '/senv service', uid='89')  # host grants, plugin rejects
        assert SAFE_ERROR == await dispatch(manager, runner, '/senv service',
                                            platform=Platform.DISCORD, uid='88')  # same numeric ID, wrong platform
        assert not (home / '.env').exists()
        assert not (home / 'secrets-ingress').exists()


@pytest.mark.asyncio
async def test_two_platforms_write_separate_targets_through_real_https(tmp_path, monkeypatch):
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings.update(allowed_telegram_user_ids=[88], allowed_owners={'discord': ['opaque-user:A']},
                    mini_app_enabled=False,
                    profiles={'telegram-service': {'target_mode': 'hermes', 'keys': ['TELEGRAM_FIXTURE']},
                              'discord-service': {'target_mode': 'hermes', 'keys': ['DISCORD_FIXTURE']}})
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', '88,opaque-user:A')
    with registered(monkeypatch, home, settings=settings, trust_roots=root) as (manager, runner):
        for platform, uid, profile, key, value in (
                (Platform.TELEGRAM, '88', 'telegram-service', 'TELEGRAM_FIXTURE', 'telegram-fixture'),
                (Platform.DISCORD, 'opaque-user:A', 'discord-service', 'DISCORD_FIXTURE', 'discord-fixture')):
            reply = await dispatch(manager, runner, '/senv ' + profile, platform=platform, uid=uid)
            assert 'One-time form sent' in reply and 'https://' not in reply
            token = token_from(runner)
            if key == 'TELEGRAM_FIXTURE':
                assert not (home / '.env').exists()
            status, data = await asyncio.to_thread(post, settings, root, '/submit',
                                                    {'token': token, 'initData': '', 'values': [value]})
            assert (status, data) == (200, {'added': [key]})
            assert dotenv_values(home / '.env', interpolate=False)[key] == value
            # Keep a fresh session/listener alive so replay is rejected by the
            # server rather than racing the intentional post-consumption shutdown.
            count = len(runner.sent)
            assert 'One-time form sent' in await dispatch(manager, runner, '/senv ' + profile,
                                                   platform=platform, uid=uid)
            assert len(runner.sent) == count + 1
            again, _ = await asyncio.to_thread(post, settings, root, '/submit',
                                                {'token': token, 'initData': '', 'values': ['replay']})
            assert again == 410
        assert dotenv_values(home / '.env', interpolate=False) == {
            'TELEGRAM_FIXTURE': 'telegram-fixture', 'DISCORD_FIXTURE': 'discord-fixture'}
        before = (home / '.env').read_bytes()
        assert SAFE_ERROR == await dispatch(manager, runner, '/senv telegram-service',
                                            platform=Platform.DISCORD, uid='88')
        assert (home / '.env').read_bytes() == before


@pytest.mark.asyncio
async def test_concurrent_profiles_and_cross_home_route_rejection(tmp_path, monkeypatch):
    second = tmp_path / 'second'
    second.mkdir()
    fixtures = []
    for base, key in ((tmp_path, 'FIRST_FIXTURE'), (second, 'SECOND_FIXTURE')):
        sample, settings, home, root = make_runtime(base)
        sample.close()
        settings.update(allowed_telegram_user_ids=[88], allowed_owners={'discord': ['opaque-user:A']},
                        mini_app_enabled=False,
                        profiles={'service': {'target_mode': 'hermes', 'keys': [key]}})
        fixtures.append((settings, home, root, key))
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', 'opaque-user:A')
    with registered(monkeypatch, fixtures[0][1], settings=fixtures[0][0], trust_roots=fixtures[0][2]) as (first, runner):
        with registered(monkeypatch, fixtures[1][1], settings=fixtures[1][0], trust_roots=fixtures[1][2]) as (other, second_runner):
            replies = await asyncio.gather(
                dispatch(first, runner, '/senv service', platform=Platform.TELEGRAM, uid='88'),
                dispatch(other, second_runner, '/senv service', platform=Platform.DISCORD, uid='opaque-user:A'))
            assert all('One-time form sent' in reply and 'https://' not in reply for reply in replies)
            for message, (settings, home, root, key) in zip((runner.sent[-1], second_runner.sent[-1]), fixtures):
                status, data = await asyncio.to_thread(post, settings, root, '/submit',
                                            {'token': token_from_message(message[2]), 'initData': '', 'values': [key.lower()]})
                assert (status, data) == (200, {'added': [key]})
                assert dotenv_values(home / '.env', interpolate=False) == {key: key.lower()}
            # A routed source for the other profile must not gain this manager's capability.
            wrong_source = SessionSource(platform=Platform.TELEGRAM, user_id='88',
                                         chat_id='trusted', chat_type='group', profile='other-profile')
            before = [(home / '.env').read_bytes() for _, home, _, _ in fixtures]
            mismatch = await dispatch(first, runner, '/senv service', source=wrong_source)
            assert mismatch is None or 'https://' not in mismatch
            assert [(home / '.env').read_bytes() for _, home, _, _ in fixtures] == before
