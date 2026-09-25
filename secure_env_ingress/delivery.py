"""Route bearer links only to the bound conversation or canonical platform home."""
from __future__ import annotations




class Delivery:
    def __init__(self, mode, selected_home):
        if mode not in ('this_chat', 'home'):
            raise ValueError('invalid delivery')
        self.mode = mode
        self.home = selected_home

    def target(self, platform, chat_id, thread_id=None):
        if self.mode == 'this_chat':
            if not chat_id:
                raise ValueError('unbound chat')
            return str(chat_id), str(thread_id) if thread_id else None
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        scope = set_hermes_home_override(self.home)
        try:
            from gateway.config import load_gateway_config, Platform
            home = load_gateway_config().get_home_channel(Platform(platform))
            if home is None or not home.chat_id:
                raise ValueError('platform home not configured')
            return str(home.chat_id), str(home.thread_id) if home.thread_id else None
        finally:
            reset_hermes_home_override(scope)

    async def send_gateway(self, gateway, platform, chat_id, thread_id, text):
        import asyncio
        loop = getattr(gateway, '_gateway_loop', None)
        if loop is None:
            raise ValueError('gateway loop unavailable')
        if loop is asyncio.get_running_loop():
            return await self._send_gateway_on_loop(gateway, platform, chat_id, thread_id, text)
        if not loop.is_running() or loop.is_closed():
            raise ValueError('gateway loop unavailable')
        work = self._send_gateway_on_loop(gateway, platform, chat_id, thread_id, text)
        try:
            future = asyncio.run_coroutine_threadsafe(work, loop)
        except BaseException:
            work.close()
            raise
        try:
            return await asyncio.wrap_future(future)
        except asyncio.CancelledError:
            future.cancel()
            raise

    async def _send_gateway_on_loop(self, gateway, platform, chat_id, thread_id, text):
        from gateway.config import Platform
        from gateway.delivery import resolve_delivery_transport
        destination, thread = self.target(platform, chat_id, thread_id)
        # The transport must belong to this selected profile, never an unrelated multiplex island.
        from hermes_constants import profile_name_for_home, set_hermes_home_override, reset_hermes_home_override
        name = profile_name_for_home(self.home) or 'default'
        scope = set_hermes_home_override(self.home)
        try:
            from gateway.config import load_gateway_config
            config = load_gateway_config()
            # Gateway's authorization map also handles named primaries and explicitly
            # routed shared-bot satellites. Never guess a different profile's bot.
            adapters = gateway._adapters_for_profile(name)
            transport = resolve_delivery_transport(Platform(platform), config, adapters)
            if transport is None:
                raise ValueError('delivery transport unavailable')
            metadata = {'thread_id': thread} if thread else {}
            # Relay needs the configured home identity even with an empty chat cache.
            home = config.get_home_channel(Platform(platform)) if transport.is_relay else None
            if home is not None and str(home.chat_id) == destination:
                metadata.update({key: value for key, value in
                                 (('user_id', home.user_id), ('scope_id', home.scope_id)) if value})
            result = await transport.send(Platform(platform), destination, text, metadata)
        finally:
            reset_hermes_home_override(scope)
        if (result.get('success') if isinstance(result, dict)
                else getattr(result, 'success', None)) is not True:
            raise ValueError('delivery failed')
        return result
