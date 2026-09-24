from pathlib import Path
import pytest
import shutil

from hermes_cli.plugins import PluginManager


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("runtime_only", [False, True])
def test_real_directory_plugin_discovery_and_unload(tmp_path, monkeypatch, runtime_only):
    home = tmp_path / 'home'
    plugin = home / 'plugins' / 'secure-env-ingress'
    plugin.mkdir(parents=True)
    if runtime_only:
        shutil.copytree(ROOT / 'secure_env_ingress', plugin, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
    else:
        for name in ('plugin.yaml', '__init__.py'):
            shutil.copy2(ROOT / name, plugin / name)
        shutil.copytree(ROOT / 'secure_env_ingress', plugin / 'secure_env_ingress', ignore=shutil.ignore_patterns('__pycache__'))
    (home / 'config.yaml').write_text('plugins:\n  enabled: [secure-env-ingress]\n')
    monkeypatch.setenv('HERMES_HOME', str(home))
    manager = PluginManager()
    manager.discover_and_load()
    assert not manager.get_platform_handler_factories('telegram')
    assert 'senv' in manager._plugin_commands
    assert manager._hooks['pre_gateway_dispatch']
    assert not (home / 'secrets-ingress').exists()
    manager.unload()
    assert 'senv' not in manager._plugin_commands
    assert not (home / 'secrets-ingress').exists()
