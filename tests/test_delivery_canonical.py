"""Gateway canonical adapter selection and cold-cache Relay home addressing."""
from types import SimpleNamespace

import pytest
from gateway.config import GatewayConfig, Platform
from gateway.run import GatewayRunner

from secure_env_ingress.delivery import Delivery


class Native:
    def __init__(self):
        self.sent = []

    async def send(self, chat_id, content, metadata=None):
        self.sent.append((chat_id, content, metadata))
        return SimpleNamespace(success=True)


class Relay:
    def __init__(self):
        self.sent = []
        self.chat_cache = {}  # no inbound route cached yet

    def fronts_platform(self, platform):
        return platform == Platform.TELEGRAM

    async def send_for_platform(self, platform, chat_id, content, metadata=None):
        self.sent.append((platform, chat_id, content, metadata))
        return SimpleNamespace(success=True)


@pytest.mark.asyncio
async def test_canonical_named_primary_and_shared_satellite_and_unserved_fail_closed(tmp_path, monkeypatch):
    from gateway import config
    import gateway.run as run
    import hermes_constants

    home = tmp_path / 'selected'
    home.mkdir()
    monkeypatch.setattr(hermes_constants, 'profile_name_for_home', lambda _: 'named')
    loaded = SimpleNamespace(platforms={}, get_home_channel=lambda _: SimpleNamespace(
        chat_id='home', thread_id=None))
    monkeypatch.setattr(config, 'load_gateway_config', lambda: loaded)
    primary = Native()
    runner = object.__new__(GatewayRunner)
    runner.adapters = {Platform.TELEGRAM: primary}
    runner._profile_adapters = {}
    runner._primary_profile_name = 'named'
    runner.config = GatewayConfig()
    await Delivery('this_chat', home).send_gateway(runner, 'telegram', 'origin', None, 'one')
    assert primary.sent == [('origin', 'one', {})]

    monkeypatch.setattr(hermes_constants, 'profile_name_for_home', lambda _: 'satellite')
    runner.config = GatewayConfig(multiplex_profiles=True, profile_routes=[SimpleNamespace(
        enabled=True, profile='satellite', bot_profile=None)])
    runner._profile_adapters = {'satellite': {}}
    monkeypatch.setattr(run, '_multiplex_profile_homes', lambda _: [('satellite', home)])
    await Delivery('home', home).send_gateway(runner, 'telegram', 'origin', None, 'two')
    assert primary.sent[-1] == ('home', 'two', {})

    # A missing secondary bot, or one explicitly failed, must never borrow primary.
    runner._profile_adapters = {'unserved': {}}
    monkeypatch.setattr(hermes_constants, 'profile_name_for_home', lambda _: 'unserved')
    with pytest.raises(ValueError, match='transport unavailable'):
        await Delivery('this_chat', home).send_gateway(runner, 'telegram', 'origin', None, 'three')
    assert len(primary.sent) == 2
    monkeypatch.setattr(hermes_constants, 'profile_name_for_home', lambda _: 'satellite')
    runner._profile_adapters = {'satellite': {}}
    runner._profile_failed_platforms = {'satellite': {Platform.TELEGRAM}}
    with pytest.raises(ValueError, match='transport unavailable'):
        await Delivery('this_chat', home).send_gateway(runner, 'telegram', 'origin', None, 'four')
    assert len(primary.sent) == 2


@pytest.mark.asyncio
async def test_cold_cache_scoped_relay_home_identity_and_no_identity_bleed(tmp_path, monkeypatch):
    from gateway import config
    import hermes_constants

    home = tmp_path / 'relay-profile'
    home.mkdir()
    monkeypatch.setattr(hermes_constants, 'profile_name_for_home', lambda _: 'relay-profile')
    canonical = SimpleNamespace(chat_id='home-room', thread_id='home-topic',
                                user_id='owner-7', scope_id='workspace-8')
    monkeypatch.setattr(config, 'load_gateway_config', lambda: SimpleNamespace(
        get_home_channel=lambda _: canonical, platforms={}))
    relay = Relay()
    runner = object.__new__(GatewayRunner)
    runner.adapters = {Platform.TELEGRAM: Native()}
    runner._profile_adapters = {'relay-profile': {Platform.RELAY: relay}}
    runner._primary_profile_name = 'default'
    await Delivery('home', home).send_gateway(runner, 'telegram', 'origin', 'source-thread', 'link')
    assert relay.sent == [(Platform.TELEGRAM, 'home-room', 'link', {
        'thread_id': 'home-topic', 'user_id': 'owner-7', 'scope_id': 'workspace-8'})]
    await Delivery('this_chat', home).send_gateway(runner, 'telegram', 'other-room', 'other-thread', 'link2')
    assert relay.sent[-1] == (Platform.TELEGRAM, 'other-room', 'link2', {'thread_id': 'other-thread'})
    await Delivery('this_chat', home).send_gateway(runner, 'telegram', 'home-room', None, 'link3')
    assert relay.sent[-1] == (Platform.TELEGRAM, 'home-room', 'link3', {
        'user_id': 'owner-7', 'scope_id': 'workspace-8'})
