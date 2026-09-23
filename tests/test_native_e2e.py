from urllib.parse import urlsplit
from unittest.mock import patch
import asyncio
import pytest
import telegram
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from secure_env_ingress.plugin import register
from secure_env_ingress.runtime import IngressRuntime
from test_phase0_compatibility import _connected_telegram, _telegram_update, _source
from gateway.session import build_session_key
from test_runtime_e2e import make_runtime, post


@pytest.mark.asyncio
async def test_native_command_busy_to_https_write_and_unload(tmp_path, monkeypatch, caplog):
    caplog.set_level("INFO", logger="secure_env_ingress.plugin")
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings['allowed_telegram_user_ids'] = [88]
    monkeypatch.setenv('HERMES_HOME', str(home))
    manager = PluginManager()
    ctx = PluginContext(manifest=PluginManifest(name='secure-env-ingress', version='0.1.0'), manager=manager)
    import yaml
    config = {'plugins': {'entries': {'secure-env-ingress': {'settings': settings}}}}
    (home / 'config.yaml').write_text(yaml.safe_dump(config))
    with patch('hermes_cli.plugins.load_config_readonly', return_value=config):
        register(ctx)
    replies = []
    async def reply(message, text, **kwargs):
        replies.append((text, kwargs))
    monkeypatch.setattr(telegram.Message, 'reply_text', reply)
    def test_runtime(config, active_home, bot_token):
        return IngressRuntime(config, active_home, bot_token, trust_roots=root)
    monkeypatch.setattr('secure_env_ingress.runtime.IngressRuntime', test_runtime)
    try:
        async with _connected_telegram(monkeypatch, manager) as (adapter, app):
            adapter._active_sessions[build_session_key(_source())] = asyncio.Event()
            await app.process_update(_telegram_update(app.bot, '/senv service'))
            adapter._message_handler.assert_not_awaited()
        assert len(replies) == 1
        assert any("Telegram handler registered; pid=" in r.message for r in caplog.records)
        assert "native-test-fixture" not in caplog.text
        url = replies[0][1]['reply_markup'].inline_keyboard[0][0].url
        token = urlsplit(url).fragment
        status, _ = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['native-test-fixture']})
        assert status == 200
        assert (home / '.env').exists()
        assert 'native-test-fixture' not in repr(replies)
    finally:
        manager.unload()
