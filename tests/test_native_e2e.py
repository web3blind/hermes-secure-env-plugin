"""Legacy transport regression, now exercised through the public generic gateway API."""
from urllib.parse import urlsplit

import pytest
from dotenv import dotenv_values
from gateway.config import Platform

from generic_helpers import registered, dispatch
from test_runtime_e2e import make_runtime, post


@pytest.mark.asyncio
async def test_group_link_https_write_replay_and_unload(tmp_path, monkeypatch):
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88')
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings['allowed_telegram_user_ids'] = [88]
    settings['mini_app_enabled'] = False
    with registered(monkeypatch, home, settings=settings, trust_roots=root) as (manager, runner):
        reply = await dispatch(manager, runner, '/SENV@Bot service', platform=Platform.TELEGRAM,
                               uid='88', chat='group')
        assert 'Do not forward' in reply and 'https://' in reply
        token = urlsplit(reply.split('https://', 1)[1].split()[0].join(['https://', ''])).fragment
        status, _ = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['native-test-fixture']})
        assert status == 200
        assert dotenv_values(home / '.env', interpolate=False)['SERVICE_TOKEN'] == 'native-test-fixture'
        assert post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['again']})[0] == 410
        assert 'native-test-fixture' not in repr(reply)
    assert not manager._plugin_commands.get('senv')
