"""Cross-loop delivery exercises real gateway transport resolution, without network sends."""
import asyncio
import contextvars
import threading
from types import SimpleNamespace

import pytest
from gateway.config import GatewayConfig, Platform
from gateway.run import GatewayRunner
from hermes_constants import get_hermes_home

from secure_env_ingress.delivery import Delivery


def running_loop():
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def serve():
        asyncio.set_event_loop(loop)
        loop.call_soon(ready.set)
        loop.run_forever()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(3)
    return loop, thread


def stop_loop(loop, thread):
    loop.call_soon_threadsafe(loop.stop)
    thread.join(3)
    assert not thread.is_alive()
    loop.close()


def gateway_with_adapter(loop, adapter):
    gateway = object.__new__(GatewayRunner)
    gateway._gateway_loop = loop
    gateway.adapters = {Platform.TELEGRAM: adapter}
    gateway._profile_adapters = {}
    gateway._primary_profile_name = 'default'
    gateway.config = GatewayConfig()
    return gateway


def test_cross_loop_real_transport_once_and_context(tmp_path, monkeypatch):
    home = tmp_path / 'selected'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    marker = contextvars.ContextVar('delivery_marker', default='missing')
    sent = []
    loop, thread = running_loop()

    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            sent.append((asyncio.get_running_loop(), marker.get(), get_hermes_home(),
                         chat_id, content, metadata))
            return SimpleNamespace(success=True)

    try:
        gateway = gateway_with_adapter(loop, Adapter())

        async def dispatch():
            token = marker.set('request-context')
            try:
                return await Delivery('this_chat', home).send_gateway(
                    gateway, 'telegram', 'room', 'topic', 'opaque fixture')
            finally:
                marker.reset(token)

        assert asyncio.run(dispatch()).success is True
        assert sent == [(loop, 'request-context', home, 'room', 'opaque fixture',
                         {'thread_id': 'topic'})]
    finally:
        stop_loop(loop, thread)


def test_cross_loop_cancellation_cancels_transport_once(tmp_path):
    home = tmp_path / 'selected'
    home.mkdir()
    entered = threading.Event()
    cancelled = threading.Event()
    sent = []
    loop, thread = running_loop()

    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            sent.append(content)
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

    async def dispatch(gateway):
        task = asyncio.create_task(Delivery('this_chat', home).send_gateway(
            gateway, 'telegram', 'room', None, 'opaque fixture'))
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await asyncio.to_thread(cancelled.wait, 3)

    try:
        asyncio.run(dispatch(gateway_with_adapter(loop, Adapter())))
        assert sent == ['opaque fixture']
    finally:
        stop_loop(loop, thread)


@pytest.mark.asyncio
async def test_missing_and_stopped_gateway_loop_fail_closed(tmp_path):
    class Adapter:
        def __init__(self):
            self.calls = 0

        async def send(self, *args, **kwargs):
            self.calls += 1
            return SimpleNamespace(success=True)

    adapter = Adapter()
    gateway = gateway_with_adapter(None, adapter)
    delivery = Delivery('this_chat', tmp_path)
    with pytest.raises(ValueError, match='gateway loop unavailable'):
        await delivery.send_gateway(gateway, 'telegram', 'room', None, 'opaque fixture')
    stopped = asyncio.new_event_loop()
    try:
        gateway._gateway_loop = stopped
        with pytest.raises(ValueError, match='gateway loop unavailable'):
            await delivery.send_gateway(gateway, 'telegram', 'room', None, 'opaque fixture')
    finally:
        stopped.close()
    with pytest.raises(ValueError, match='gateway loop unavailable'):
        await delivery.send_gateway(gateway, 'telegram', 'room', None, 'opaque fixture')
    assert adapter.calls == 0
