"""Disposable real Hermes profile-scoped gateway ingress harness."""
import asyncio
import inspect
from contextlib import contextmanager
from pathlib import Path

import yaml
from gateway.config import GatewayConfig, Platform
from gateway.platforms.event import MessageEvent
from gateway.run import GatewayRunner, _profile_runtime_scope
from gateway.session import SessionSource
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from secure_env_ingress.runtime import IngressRuntime as RealRuntime
from secure_env_ingress.plugin import register


@contextmanager
def registered(monkeypatch, home: Path, *, settings=None, config=None, trust_roots=None):
    if config is None:
        config = {'plugins': {'entries': {'secure-env-ingress': {'settings': settings}}}}
    home.joinpath('config.yaml').write_text(yaml.safe_dump(config), encoding='utf-8')
    home.joinpath('config.yaml').chmod(0o600)
    manager = PluginManager(scope_key=str(home))
    ctx = PluginContext(PluginManifest(name='secure-env-ingress', version='0.2.0'), manager)
    import hermes_cli.plugins as plugins
    monkeypatch.setattr(plugins, '_plugin_manager', None)
    monkeypatch.setitem(plugins._plugin_managers_by_home, home.resolve(), manager)
    manager._discovered = True
    if trust_roots is not None:
        from secure_env_ingress import runtime as ingress_runtime
        original = ingress_runtime.IngressRuntime
        def disposable_runtime(cfg, selected_home, token):
            if Path(selected_home) == home:
                return RealRuntime(cfg, selected_home, token, trust_roots=trust_roots)
            return original(cfg, selected_home, token)
        monkeypatch.setattr(ingress_runtime, 'IngressRuntime', disposable_runtime)
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner.sent = []
    class RecordingAdapter:
        def __init__(self, platform):
            self.platform = platform
        async def send(self, chat_id, content, metadata=None):
            from types import SimpleNamespace
            runner.sent.append((self.platform, chat_id, content, metadata))
            return SimpleNamespace(success=True)
    runner.adapters = {platform: RecordingAdapter(platform)
                       for platform in (Platform.TELEGRAM, Platform.DISCORD)}
    runner._profile_adapters = {}
    runner._primary_profile_name = 'default'
    runner._gateway_loop = None  # Bound by async dispatch, as GatewayRunner.run does.
    runner.session_store = None
    runner._running_agents = {}
    runner._pending_messages = {}
    # The test never enters an agent turn. No mocking of authentication, lifecycle,
    # plugin dispatch, capability creation, or the HTTPS writer.
    monkeypatch.setattr('hermes_cli.plugins.load_config_readonly',
                        lambda: yaml.safe_load(Path(__import__('hermes_constants').get_hermes_home()).joinpath('config.yaml').read_text()))
    with _profile_runtime_scope(home, {}):
        register(ctx)
    assert 'senv' in manager._plugin_commands
    try:
        yield manager, runner
    finally:
        manager.unload()


async def dispatch(manager, runner, text, *, platform=Platform.TELEGRAM, uid='88',
                   chat='group', chat_id='trusted', source=None, home=None):
    if source is None:
        source = SessionSource(platform=platform, user_id=uid, chat_id=chat_id, chat_type=chat)
    event = MessageEvent(source=source, text=text)
    runner._gateway_loop = asyncio.get_running_loop()
    if home is None:
        home = manager.home_path
    with _profile_runtime_scope(home, {}):
        from hermes_cli.plugins import get_plugin_manager, get_plugin_command_handler
        assert get_plugin_manager() is manager, (get_plugin_manager().scope_key, manager.scope_key)
        assert get_plugin_command_handler('senv') is manager._plugin_commands['senv']['handler']
        result = runner._handle_message(event)
        return await result if inspect.isawaitable(result) else result
