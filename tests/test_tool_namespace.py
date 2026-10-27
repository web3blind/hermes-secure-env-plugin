"""Native Vault and Secure ENV must register and unload without shadowing."""
import json
import shutil
from pathlib import Path

import pytest

from hermes_cli.plugins import PluginManager
from tools import browser_vault_tool as native
from tools.registry import registry

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('runtime_only', [False, True])
def test_native_and_plugin_names_are_independent(tmp_path, monkeypatch, runtime_only):
    home = tmp_path / 'home'
    destination = home / 'plugins' / 'secure-env-ingress'
    home.mkdir(parents=True)
    if runtime_only:
        shutil.copytree(ROOT / 'secure_env_ingress', destination, dirs_exist_ok=True)
    elif (ROOT / 'plugin.yaml').is_file():
        destination.mkdir(parents=True)
        for name in ('plugin.yaml', '__init__.py'):
            shutil.copy2(ROOT / name, destination / name)
        shutil.copytree(ROOT / 'secure_env_ingress', destination / 'secure_env_ingress')
    else:
        # Wheels intentionally ship the package entrypoint, not the checkout's
        # root directory-plugin shim. Exercise that real distribution surface.
        from importlib.metadata import entry_points
        entrypoint = next(ep for ep in entry_points(group='hermes_agent.plugins')
                          if ep.name == 'secure-env-ingress')
        assert Path(entrypoint.load().__file__).resolve().is_relative_to(ROOT)
    (home / 'config.yaml').write_text('plugins:\n  enabled: [secure-env-ingress]\n  entries:\n    secure-env-ingress:\n      settings:\n        allowed_telegram_user_ids: [7]\n')
    monkeypatch.setenv('HERMES_HOME', str(home))
    # Import registers the real native tool(s), not a fake placeholder.
    native_names = ['browser_vault'] if hasattr(native, 'BROWSER_VAULT_SCHEMA') else ['browser_vault_list', 'browser_vault_fill']
    before = {name: registry.get_entry(name, scope=str(home)) for name in native_names}
    assert all(before.values())
    manager = PluginManager(scope_key=str(home))
    import hermes_cli.plugins as plugins
    monkeypatch.setattr(plugins, '_plugin_manager', None)
    monkeypatch.setitem(plugins._plugin_managers_by_home, home.resolve(), manager)
    try:
        manager.discover_and_load()
        entry = registry.get_entry('secure_env_vault', scope=str(home))
        assert entry is not None, 'Secure ENV tool must survive native Vault registration'
        assert entry.schema['name'] == 'secure_env_vault'
        assert 'browser_vault' not in manager._plugin_tool_names
        for name, original in before.items():
            assert registry.get_entry(name, scope=str(home)) is original
        assert manager._hooks.get('pre_gateway_dispatch')
        assert 'senv' in manager._plugin_commands
        result = json.loads(registry.dispatch('secure_env_vault', {
            'origin': 'https://synthetic.test', 'label': 'Synthetic'}, task_id='unbound', session_id='unbound'))
        assert result['success'] is False and result['reason'] == 'session_binding'
        assert 'synthetic.test' not in json.dumps(result)
        from gateway import session_context as sc
        for owner, profile in [('8', ''), ('7', 'foreign-profile')]:
            tokens = sc.set_session_vars(platform='telegram', user_id=owner,
                chat_id='7', chat_type='dm', session_id='task', session_key='key',
                profile=profile, cron_session='')
            try:
                denied = json.loads(registry.dispatch('secure_env_vault', {
                    'origin': 'https://synthetic.test', 'label': 'Synthetic'},
                    task_id='task', session_id='task'))
            finally:
                sc.clear_session_vars(tokens)
            assert denied['success'] is False and denied['reason'] == 'session_binding'
            assert 'synthetic.test' not in json.dumps(denied)
        assert not (home / 'secrets-ingress').exists()
    finally:
        manager.unload()
    for name in ('secure_env_vault', 'secure_payment_fill', 'secure_operation'):
        assert registry.get_entry(name, scope=str(home)) is None
    assert not manager._hooks.get('pre_gateway_dispatch')
    assert 'senv' not in manager._plugin_commands
    for name, original in before.items():
        assert registry.get_entry(name, scope=str(home)) is original
