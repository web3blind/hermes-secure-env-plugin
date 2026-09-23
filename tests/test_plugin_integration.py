from pathlib import Path
import pytest
import shutil
from types import SimpleNamespace
from unittest.mock import MagicMock

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
    factories = manager.get_platform_handler_factories('telegram')
    assert len(factories) == 1
    app = SimpleNamespace(bot=SimpleNamespace(token='111:offline'), add_handler=MagicMock(), remove_handler=MagicMock())
    factory, _ = factories[0]
    factory(app, None)
    app.add_handler.assert_called_once()
    assert not (home / 'secrets-ingress').exists()
    manager.unload()
    app.remove_handler.assert_called_once()
    assert not (home / 'secrets-ingress').exists()
