"""Exercise the installed wheel against an unmodified ruamel-based host."""
# ruff: noqa: E402
# Host imports intentionally follow isolated HOME and entrypoint assertions.
import importlib.util
from importlib.metadata import entry_points, distributions
import json
import os
from pathlib import Path

assert importlib.util.find_spec('yaml') is None, 'PyYAML must really be absent'
assert not any(d.metadata['Name'].lower() == 'pyyaml' for d in distributions())
home = Path(os.environ['HERMES_HOME'])
home.mkdir(mode=0o700, parents=True, exist_ok=True)
config = home / 'config.yaml'
config.write_text('plugins:\n  enabled: [secure-env-ingress]\n')
config.chmod(0o600)
ep = next(ep for ep in entry_points(group='hermes_agent.plugins') if ep.name == 'secure-env-ingress')
module = ep.load()
assert callable(module.register)
assert Path(module.__file__).is_relative_to(Path(os.environ['SENV_WHEEL_ROOT']))
from hermes_cli.plugins import PluginManager
from tools.registry import registry
from tools import browser_vault_tool as native
native_names = ['browser_vault'] if hasattr(native, 'BROWSER_VAULT_SCHEMA') else ['browser_vault_list', 'browser_vault_fill']
native_entries = {name: registry.get_entry(name, scope=str(home)) for name in native_names}
assert all(native_entries.values())
manager = PluginManager(scope_key=str(home))
manager.discover_and_load()
assert 'senv' in manager._plugin_commands, manager._plugin_commands
assert manager._hooks.get('pre_gateway_dispatch')
for name in ('secure_env_vault', 'secure_payment_fill', 'secure_operation'):
    assert registry.get_entry(name, scope=str(home)), name
for name, entry in native_entries.items():
    assert registry.get_entry(name, scope=str(home)) is entry
manager.unload()
for name in ('secure_env_vault', 'secure_payment_fill', 'secure_operation'):
    assert registry.get_entry(name, scope=str(home)) is None
for name, entry in native_entries.items():
    assert registry.get_entry(name, scope=str(home)) is entry
from secure_env_ingress.setup_config import _read_config_file, SetupConfigError
cases = ['a: [unfinished', 'a: 1\na: 2\n', 'base: &b {a: 1}\nother: {<<: *b, a: 2}\n']
for text in cases:
    config.write_text(text)
    try:
        _read_config_file(config, os.getuid())
    except SetupConfigError:
        pass
    else:
        raise AssertionError('unsafe config accepted')
config.write_text('enabled: yes\nbase: &b {x: 1}\nother: {<<: *b, y: 2}\n')
loaded, _, _ = _read_config_file(config, os.getuid())
assert loaded == {'enabled': True, 'base': {'x': 1}, 'other': {'x': 1, 'y': 2}}
assert importlib.util.find_spec('yaml') is None
print(json.dumps({'entrypoint': ep.value, 'package_path': module.__file__, 'no_pyyaml': True,
                  'registration': True, 'strict_yaml': True, 'unload': True}))
