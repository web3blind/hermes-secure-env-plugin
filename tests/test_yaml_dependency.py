"""Runtime YAML independence and strict read-only config boundaries."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


def test_runtime_import_and_registration_without_pyyaml(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = '''
import importlib.abc
import sys
# The installed historical host still uses PyYAML; the plugin must not.
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
class NoPyYaml(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'yaml' or fullname.startswith('yaml.'):
            raise ModuleNotFoundError('PyYAML deliberately unavailable')
for name in list(sys.modules):
    if name == "yaml" or name.startswith("yaml."):
        del sys.modules[name]
blocker = NoPyYaml()
sys.meta_path.insert(0, blocker)
from secure_env_ingress import setup_config
from secure_env_ingress.plugin import register
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
manager = PluginManager()
try:
    register(PluginContext(PluginManifest(name='secure-env-ingress', version='test'), manager))
    assert 'senv' in manager._plugin_commands
finally:
    # Legacy host teardown imports unrelated PyYAML-dependent core modules.
    sys.meta_path.remove(blocker)
    manager.unload()
'''
    env = {**os.environ, 'HOME': str(tmp_path), 'HERMES_HOME': str(tmp_path),
           'PYTHONPATH': os.pathsep.join([str(root), os.environ.get('PYTHONPATH', '')])}
    result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('text', [
    'a: 1\na: 2\n', 'outer:\n  a: 1\n  a: 2\n',
    'base: &base {a: 1}\nother: {<<: *base, a: 2}\n',
    'base: &base {a: 1}\nother: {<<: [*base, *base]}\n',
    'a: [unfinished', '!!python/object/apply:os.system [false]',
    '[not, a, mapping]', 'a: 1\n---\nb: 2\n',
])
def test_config_rejects_unsafe_or_ambiguous_yaml(tmp_path, text):
    from secure_env_ingress.setup_config import SetupConfigError, _read_config_file
    path = tmp_path / 'config.yaml'
    path.write_text(text)
    path.chmod(0o600)
    before = path.read_bytes()
    with pytest.raises(SetupConfigError):
        _read_config_file(path, os.getuid())
    assert path.read_bytes() == before


@pytest.mark.parametrize('directive', ['', '%YAML 1.1\n---\n', '%YAML 1.2\n---\n'])
def test_config_preserves_yaml11_scalar_and_merge_semantics(tmp_path, directive):
    from secure_env_ingress.setup_config import _read_config_file
    path = tmp_path / 'config.yaml'
    path.write_text(directive + 'enabled: yes\ndisabled: off\noctal: 012\nbase: &base {x: 1}\nother: {<<: *base, y: 2}\nexponent: 1e3\nnew_octal: 0o12\n')
    path.chmod(0o600)
    loaded, _, _ = _read_config_file(path, os.getuid())
    assert loaded == {'enabled': True, 'disabled': False, 'octal': 10,
                      'base': {'x': 1}, 'other': {'x': 1, 'y': 2},
                      'exponent': '1e3', 'new_octal': '0o12'}


@pytest.mark.parametrize('hour', [1, 12])
@pytest.mark.parametrize('fraction', ['1234569', '9999999'])
def test_timestamp_microseconds_are_truncated(tmp_path, fraction, hour):
    import datetime
    from secure_env_ingress.setup_config import _read_config_file
    path = tmp_path / 'config.yaml'
    path.write_text(f'value: 2026-10-08T{hour}:34:59.{fraction}Z\n')
    path.chmod(0o600)
    loaded, _, _ = _read_config_file(path, os.getuid())
    assert loaded['value'] == datetime.datetime(
        2026, 10, 8, hour, 34, 59, int(fraction[:6]), tzinfo=datetime.timezone.utc
    )


def test_read_settings_optional_only(tmp_path, monkeypatch):
    import inspect
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
    from hermes_constants import get_hermes_home
    from secure_env_ingress.plugin import register
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    manager = PluginManager(scope_key=str(tmp_path))
    ctx = PluginContext(PluginManifest(name='secure-env-ingress', version='test'), manager)
    monkeypatch.setattr('hermes_cli.plugins.load_config_readonly', lambda: {})
    register(ctx)
    command_entry = manager._plugin_commands['senv']
    command = command_entry.handler if hasattr(command_entry, 'handler') else command_entry['handler']
    read_settings = inspect.getclosurevars(command).nonlocals['read_settings']
    sentinel = RuntimeError('private config contents')
    def broken():
        raise sentinel
    monkeypatch.setattr('hermes_cli.plugins.load_config_readonly', broken)
    try:
        assert read_settings(tmp_path, consumer_config=True) is None
        with pytest.raises(RuntimeError) as caught:
            read_settings(tmp_path)
        assert caught.value is sentinel
        assert get_hermes_home() == tmp_path
    finally:
        manager.unload()

