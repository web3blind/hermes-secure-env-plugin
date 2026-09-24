"""Direct fields through Hermes generic command, HTTPS and real temp dotenv."""
from urllib.parse import urlsplit

import pytest
import yaml
from dotenv import dotenv_values
from gateway.config import Platform

from generic_helpers import registered, dispatch
from test_runtime_e2e import make_runtime, post


def token_from(reply):
    return urlsplit('https://' + reply.split('https://', 1)[1].split()[0]).fragment


@pytest.mark.asyncio
async def test_direct_fields_persist_refresh_https_submit_and_replay(tmp_path, monkeypatch):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,99')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', '88')
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings.update(allowed_telegram_user_ids=[88], mini_app_enabled=False)
    settings['profiles'] = {'test': {'target_mode': 'hermes', 'keys': ['SENV_TEST_VALUE']}}
    existing = home / '.env'
    existing.write_text('SENV_TEST_VALUE="preserve-me"\n', encoding='utf-8')
    existing.chmod(0o600)
    with registered(monkeypatch, home, settings=settings, trust_roots=root) as (manager, runner):
        reply = await dispatch(manager, runner, '/senv site_auth field1,field2')
        target = home / 'secrets-ingress' / 'site_auth.env'
        assert 'Fields: field1, field2' in reply, reply
        profile = yaml.safe_load((home / 'config.yaml').read_text())['plugins']['entries']['secure-env-ingress']['settings']['profiles']['site_auth']
        assert profile == {'target_mode': 'custom', 'target_path': str(target), 'keys': ['field1', 'field2']}
        assert not target.exists()
        token = token_from(reply)
        assert post(settings, root, '/session', {'token': token, 'initData': ''}) == (200, {'label': 'site_auth', 'keys': ['field1', 'field2']})
        values = ['fictional-first', 'fictional-second']
        assert post(settings, root, '/submit', {'token': token, 'initData': '', 'values': values}) == (200, {'added': ['field1', 'field2']})
        assert dotenv_values(target, interpolate=False)['field1'] == values[0]
        assert dotenv_values(target, interpolate=False)['field2'] == values[1]
        assert post(settings, root, '/submit', {'token': token, 'initData': '', 'values': values})[0] == 410
        reply = await dispatch(manager, runner, '/senv test lowercase,MixedCase')
        assert 'Fields: lowercase, MixedCase' in reply
        token = token_from(reply)
        assert post(settings, root, '/session', {'token': token, 'initData': ''})[1]['keys'] == ['lowercase', 'MixedCase']
        assert post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['lower-value', 'mixed-value']})[0] == 200
        assert dotenv_values(existing, interpolate=False) == {'SENV_TEST_VALUE': 'preserve-me', 'lowercase': 'lower-value', 'MixedCase': 'mixed-value'}
        assert not any(value in reply for value in values)


@pytest.mark.asyncio
async def test_direct_fields_denies_cross_platform_and_routed_profile(tmp_path, monkeypatch):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,99')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', '88')
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings.update(allowed_telegram_user_ids=[88], mini_app_enabled=False)
    with registered(monkeypatch, home, settings=settings, trust_roots=root) as (manager, runner):
        assert 'https://' not in await dispatch(manager, runner, '/senv service', platform=Platform.DISCORD, uid='88')
        assert 'https://' not in await dispatch(manager, runner, '/senv service', platform=Platform.TELEGRAM, uid='99')
        from gateway.session import SessionSource
        source = SessionSource(platform=Platform.TELEGRAM, user_id='88', chat_id='trusted', chat_type='dm', profile='other')
        assert 'https://' not in await dispatch(manager, runner, '/senv service', source=source)
        assert not (home / '.env').exists()
