"""Generic installation handoff: sanitized text, owner authorization and scope."""
import tempfile
from pathlib import Path

import pytest
from gateway.config import Platform
from gateway.platforms.event import MessageEvent
from gateway.session import SessionSource
from gateway.run import _profile_runtime_scope

from generic_helpers import registered, dispatch
from secure_env_ingress.setup_handoff import SETUP_REQUEST


@pytest.mark.asyncio
async def test_setup_falls_back_to_sanitized_request_without_injection(tmp_path, monkeypatch):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,opaque-user:A')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', 'opaque-user:A,stranger')
    home = tmp_path / 'profile'
    home.mkdir(mode=0o700)
    with registered(monkeypatch, home, settings={'allowed_owners': {'discord': ['opaque-user:A']}}) as (manager, runner):
        source = SessionSource(platform=Platform.DISCORD, user_id='opaque-user:A', chat_id='trusted', chat_type='group')
        event = MessageEvent(source=source, text='/senv setup', reply_to_text='fictional-private-secret',
                             raw_message={'text': 'fictional-private-secret'}, media_urls=['private-photo.jpg'])
        with _profile_runtime_scope(home, {}):
            reply = await runner._handle_message(event)
        assert SETUP_REQUEST in reply
        assert 'fictional-private-secret' not in reply
        assert 'private-photo.jpg' not in reply
        assert 'approval' in reply
        assert 'https://' not in reply


@pytest.mark.asyncio
async def test_setup_denies_nonowners_and_other_platform_even_in_trusted_chat(tmp_path, monkeypatch):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,opaque-user:A')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', 'opaque-user:A,stranger')
    home = tmp_path / 'profile'
    home.mkdir(mode=0o700)
    with registered(monkeypatch, home, settings={'allowed_owners': {'discord': ['opaque-user:A']}}) as (manager, runner):
        for platform, uid in ((Platform.DISCORD, 'stranger'), (Platform.TELEGRAM, 'opaque-user:A')):
            reply = await dispatch(manager, runner, '/senv setup', platform=platform, uid=uid, chat='group')
            assert SETUP_REQUEST not in reply and 'https://' not in reply


@pytest.mark.asyncio
async def test_bootstrap_only_telegram_profile_env_not_ambient(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory(dir='/tmp') as raw:
        home = Path(raw)
        home.chmod(0o700)
        env = home / '.env'
        env.write_text('TELEGRAM_ALLOWED_USERS=88\nFICTIONAL_SECRET=never-forward\n')
        env.chmod(0o600)
        # Host permits both; plugin bootstrap must independently use profile-local ID.
        monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,999')
        with registered(monkeypatch, home, settings={}) as (manager, runner):
            allowed = await dispatch(manager, runner, '/senv setup', uid='88')
            denied = await dispatch(manager, runner, '/senv setup', uid='999')
            assert SETUP_REQUEST in allowed
            assert SETUP_REQUEST not in denied
            assert 'never-forward' not in allowed


@pytest.mark.asyncio
async def test_paused_setup_refuses_without_injection(tmp_path, monkeypatch):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88,opaque-user:A')
    monkeypatch.setenv('DISCORD_ALLOWED_USERS', 'opaque-user:A,stranger')
    home = tmp_path / 'profile'
    home.mkdir(mode=0o700)
    (home / 'ESTOP').write_text('{}\n')
    with registered(monkeypatch, home, settings={'allowed_telegram_user_ids': [88]}) as (manager, runner):
        reply = await dispatch(manager, runner, '/senv setup')
        assert 'paused' in reply
        assert SETUP_REQUEST not in reply
