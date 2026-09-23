"""Run from outside the checkout with the installed wheel first on PYTHONPATH."""
import os
from pathlib import Path
import tempfile

with tempfile.TemporaryDirectory(prefix='senv-wheel-smoke-') as temporary:
    home = Path(temporary) / 'home'
    home.mkdir(mode=0o700)
    os.environ['HERMES_HOME'] = str(home)
    (home / 'config.yaml').write_text('plugins:\n  enabled: [secure-env-ingress]\n')
    import secure_env_ingress
    from importlib.metadata import entry_points
    entry = next(ep for ep in entry_points(group='hermes_agent.plugins') if ep.name == 'secure-env-ingress')
    assert callable(getattr(entry.load(), 'register', None)), 'entry point must expose a module with register(ctx)'
    assert Path(secure_env_ingress.__file__).is_relative_to(Path(os.environ['SENV_WHEEL_ROOT']))
    from hermes_cli.plugins import PluginManager
    manager = PluginManager()
    manager.discover_and_load()
    try:
        assert 'senv' in manager._plugin_commands
        assert manager.get_platform_handler_factories('telegram')
    finally:
        manager.unload()
    from test_runtime_e2e import test_real_https_write_mode_binding_replay_shutdown
    from types import SimpleNamespace
    for mini in (False, True):
        target = Path(temporary) / str(mini)
        target.mkdir()
        test_real_https_write_mode_binding_replay_shutdown(target, SimpleNamespace(text=''), mini)
    print('FRESH_WHEEL_DISCOVERY_AND_HTTPS_E2E=PASS')
