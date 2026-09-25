"""Gateway command delivery failure/cancellation never exposes a stranded bearer."""
import asyncio
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from gateway.config import Platform

from generic_helpers import dispatch, registered
from secure_env_ingress.plugin import SAFE_ERROR
from test_runtime_e2e import make_runtime


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['this_chat', 'home'])
@pytest.mark.parametrize('failure', ['result', 'exception', 'cancel'])
async def test_failed_command_send_revokes_exact_group_without_duplicate_link(
        mode, failure, tmp_path, monkeypatch):
    from gateway import config
    from secure_env_ingress import plugin

    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings.update(delivery=mode, allowed_telegram_user_ids=[88], mini_app_enabled=False)
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '88')
    monkeypatch.setattr(config, 'load_gateway_config', lambda: SimpleNamespace(
        platforms={}, get_home_channel=lambda _: SimpleNamespace(chat_id='home-room', thread_id='topic-home')))
    issued, cancelled, runtimes = [], [], []
    original_create = plugin.LazyRuntime.create_reserved
    original_cancel = plugin.LazyRuntime.cancel_group

    def create(self, *args, **kwargs):
        definition, links = original_create(self, *args, **kwargs)
        if links:
            issued.append((links['group_id'], links['url']))
            runtimes.append(self._runtime)
        return definition, links

    def cancel(self, group_id):
        cancelled.append(group_id)
        return original_cancel(self, group_id)

    monkeypatch.setattr(plugin.LazyRuntime, 'create_reserved', create)
    monkeypatch.setattr(plugin.LazyRuntime, 'cancel_group', cancel)
    entered = asyncio.Event()

    class BrokenAdapter:
        async def send(self, chat_id, content, metadata=None):
            assert chat_id == ('home-room' if mode == 'home' else 'trusted')
            assert content.count('https://') == 1
            entered.set()
            if failure == 'cancel':
                await asyncio.Event().wait()
            if failure == 'exception':
                raise RuntimeError('transport unavailable')
            return SimpleNamespace(success=False, error='transport unavailable')

    with registered(monkeypatch, home, settings=settings, trust_roots=root) as (manager, runner):
        runner.adapters[Platform.TELEGRAM] = BrokenAdapter()
        operation = asyncio.create_task(dispatch(manager, runner, '/senv service', uid='88'))
        if failure == 'cancel':
            await asyncio.wait_for(entered.wait(), 5)
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
        else:
            assert await operation == SAFE_ERROR
        assert len(issued) == 1
        assert cancelled == [issued[0][0]]
        assert runner.sent == []  # no gateway command echo of the same bearer
        # The exact issued group is revoked and cannot be redeemed.
        assert runtimes[0]._store.peek(urlsplit(issued[0][1]).fragment) is None
