"""Configured failures are local, fail closed and never disclose source/errors."""
import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml

from secure_env_ingress.operations import (
    BoundOperation, bind, clear_consumers, load_configured_consumers, register_consumer,
)

GOOD = '''from secure_env_ingress.operations import BoundOperation
def factory(raw):
    return BoundOperation('Synthetic action', lambda secret: None)
'''


def module(home, name, source=GOOD):
    path = home / (name + '.py')
    path.write_text(source)
    path.chmod(0o600)
    return {'path': str(path), 'factory': 'factory',
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('fault', ['hash', 'name', 'spec', 'path', 'permission',
                                  'directory', 'symbol', 'import', 'syntax', 'exit'])
def test_mixed_entries(tmp_path, caplog, reverse, fault):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    good = module(home, 'good')
    bad = module(home, 'bad', "raise RuntimeError('PRIVATE-DIAGNOSTIC')\n")
    name = 'bad'
    if fault == 'hash':
        bad['sha256'] = '0' * 64
    elif fault == 'name':
        name = 'PRIVATE-DIAGNOSTIC\n'
    elif fault == 'spec':
        bad = None
    elif fault == 'path':
        bad['path'] = str(home / 'missing.py')
    elif fault == 'permission':
        Path(bad['path']).chmod(0o666)
    elif fault == 'directory':
        unsafe = home / 'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        bad = module(unsafe, 'bad')
    elif fault == 'symbol':
        bad = module(home, 'bad')
        bad['factory'] = 'absent'
    elif fault == 'syntax':
        bad = module(home, 'bad', 'syntax error PRIVATE-DIAGNOSTIC')
    elif fault == 'exit':
        bad = module(home, 'bad', "raise SystemExit('PRIVATE-DIAGNOSTIC')")
    entries = [('good', good), (name, bad)]
    try:
        load_configured_consumers(home, dict(reversed(entries) if reverse else entries))
        assert bind(home, 'good', {})[0].summary == 'Synthetic action'
        with pytest.raises(ValueError):
            bind(home, 'bad', {})
        assert 'PRIVATE-DIAGNOSTIC' not in caplog.text
        assert 'consumer' in caplog.text.lower()
    finally:
        clear_consumers(home)


def test_mismatching_source_never_executes(tmp_path):
    sentinel = tmp_path / 'executed'
    bad = module(tmp_path, 'bad', f"open({str(sentinel)!r}, 'w').write('ran')")
    bad['sha256'] = '0' * 64
    load_configured_consumers(tmp_path, {'bad': bad})
    assert not sentinel.exists()
    with pytest.raises(ValueError):
        bind(tmp_path, 'bad', {})


@pytest.mark.parametrize('succeed', [False, True])
def test_module_registration_side_effects_do_not_escape(tmp_path, succeed):
    other = tmp_path / 'other'
    register_consumer(other, 'existing', lambda _: BoundOperation('Existing', lambda _: None))
    source = f'''from pathlib import Path
from secure_env_ingress.operations import register_consumer, clear_consumers, BoundOperation
clear_consumers(Path({str(other)!r}))
register_consumer(Path({str(tmp_path)!r}), 'injected', lambda _: BoundOperation('Injected', lambda _: None))
register_consumer(Path({str(other)!r}), 'injected', lambda _: BoundOperation('Injected', lambda _: None))
''' + (GOOD if succeed else "raise RuntimeError('PRIVATE-DIAGNOSTIC')")
    try:
        load_configured_consumers(tmp_path, {'bad': module(tmp_path, 'bad', source),
                                            'good': module(tmp_path, 'good')})
        assert bind(other, 'existing', {})[0].summary == 'Existing'
        assert bind(tmp_path, 'good', {})[0].summary == 'Synthetic action'
        for home in (tmp_path, other):
            with pytest.raises(ValueError):
                bind(home, 'injected', {})
        if succeed:
            assert bind(tmp_path, 'bad', {})[0].summary == 'Synthetic action'
        else:
            with pytest.raises(ValueError):
                bind(tmp_path, 'bad', {})
    finally:
        clear_consumers(tmp_path)
        clear_consumers(other)


@pytest.mark.parametrize('container', [None, [], 'PRIVATE-DIAGNOSTIC', 42])
def test_invalid_container_revokes_stale_configured_only(tmp_path, container):
    register_consumer(tmp_path, 'manual', lambda _: BoundOperation('Manual', lambda _: None))
    try:
        load_configured_consumers(tmp_path, {'good': module(tmp_path, 'good')})
        load_configured_consumers(tmp_path, container)
        with pytest.raises(ValueError):
            bind(tmp_path, 'good', {})
        assert bind(tmp_path, 'manual', {})[0].summary == 'Manual'
    finally:
        clear_consumers(tmp_path)


def test_collision_revoke_reload_and_profile(tmp_path):
    other = tmp_path / 'other'
    register_consumer(tmp_path, 'good', lambda _: BoundOperation('Stale', lambda _: None))
    register_consumer(other, 'good', lambda _: BoundOperation('Other', lambda _: None))
    spec = module(tmp_path, 'good')
    try:
        load_configured_consumers(tmp_path, {'good': spec})
        with pytest.raises(ValueError):
            bind(tmp_path, 'good', {})
        load_configured_consumers(tmp_path, {'good': spec})
        assert bind(tmp_path, 'good', {})[0].summary == 'Synthetic action'
        spec['sha256'] = '0' * 64
        load_configured_consumers(tmp_path, {'good': spec})
        with pytest.raises(ValueError):
            bind(tmp_path, 'good', {})
        clear_consumers(tmp_path)
        assert bind(other, 'good', {})[0].summary == 'Other'
    finally:
        clear_consumers(tmp_path)
        clear_consumers(other)


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('container', ['mixed', 'null', 'settings'])
def test_actual_directory_loader_keeps_all_surfaces(tmp_path, monkeypatch, reverse, container):
    from hermes_cli.plugins import PluginManager
    from tools.registry import registry
    from gateway import session_context as sc
    root = Path(__file__).resolve().parents[1]
    home = tmp_path / 'home'
    dest = home / 'plugins' / 'secure-env-ingress'
    dest.mkdir(parents=True)
    home.chmod(0o700)
    for name in ('plugin.yaml', '__init__.py'):
        shutil.copy2(root / name, dest / name)
    shutil.copytree(root / 'secure_env_ingress', dest / 'secure_env_ingress',
                    ignore=shutil.ignore_patterns('__pycache__'))
    good = module(home, 'good', f"""import sys
ops = next(m for m in list(sys.modules.values())
           if getattr(m, '__file__', None) == {str(dest / 'secure_env_ingress' / 'operations.py')!r})
def factory(public):
    return ops.BoundOperation('Synthetic action', lambda secret: None)
""")
    bad = module(home, 'bad', "raise RuntimeError('PRIVATE-DIAGNOSTIC')")
    bad['sha256'] = '0' * 64
    pairs = [('good', good), ('bad', bad)]
    settings = {'allowed_telegram_user_ids': [7], 'consumers':
                dict(reversed(pairs) if reverse else pairs)}
    if container == 'null':
        settings['consumers'] = None
    elif container == 'settings':
        settings = 'PRIVATE-DIAGNOSTIC'
    (home / 'config.yaml').write_text(yaml.safe_dump({'plugins': {
        'enabled': ['secure-env-ingress'], 'entries': {
            'secure-env-ingress': {'settings': settings}}}}, sort_keys=False))
    monkeypatch.setenv('HERMES_HOME', str(home))
    manager = PluginManager(scope_key=str(home))
    import hermes_cli.plugins as plugins
    monkeypatch.setattr(plugins, '_plugin_manager', None)
    monkeypatch.setitem(plugins._plugin_managers_by_home, home.resolve(), manager)
    try:
        manager.discover_and_load()
        assert 'senv' in manager._plugin_commands
        assert manager._hooks['pre_gateway_dispatch']
        for name in ('browser_vault', 'secure_operation', 'secure_payment_fill'):
            assert registry.get_entry(name, scope=str(home))
        import sys
        operation_handler = registry.get_entry('secure_operation', scope=str(home)).handler
        loaded_ops = sys.modules[operation_handler.__module__.rsplit('.', 1)[0] + '.operations']
        if container == 'mixed':
            bound, _ = loaded_ops.bind(home, 'good', {})
            assert bound.summary == 'Synthetic action'
            bound.execute('synthetic')
            tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7',
                chat_type='dm', session_id='sid', session_key='key', profile='', cron_session='')
            try:
                result = registry.dispatch('secure_operation', {'operation': 'bad', 'parameters': {}},
                    task_id='sid', session_id='sid')
                assert json.loads(result) == {'success': False, 'status': 'consumer_binding'}
            finally:
                sc.clear_session_vars(tokens)
        with pytest.raises(ValueError):
            loaded_ops.bind(home, 'bad', {})
        assert not (home / 'secrets-ingress').exists()
    finally:
        manager.unload()
    with pytest.raises(ValueError):
        loaded_ops.bind(home, 'good', {})


@pytest.mark.parametrize('error', [OSError, ValueError, yaml.YAMLError, RuntimeError])
def test_consumer_config_read_failure_is_scoped(tmp_path, monkeypatch, caplog, error):
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
    from secure_env_ingress.plugin import register
    from tools.registry import registry
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    def unreadable():
        raise error('PRIVATE-DIAGNOSTIC')
    monkeypatch.setattr('hermes_cli.plugins.load_config_readonly', unreadable)
    manager = PluginManager(scope_key=str(tmp_path))
    ctx = PluginContext(PluginManifest(name='secure-env-ingress', version='test'), manager)
    try:
        register(ctx)
        assert 'senv' in manager._plugin_commands
        for name in ('browser_vault', 'secure_payment_fill', 'secure_operation'):
            assert registry.get_entry(name, scope=str(tmp_path))
        assert 'invalid configuration container' in caplog.text
        assert 'PRIVATE-DIAGNOSTIC' not in caplog.text
    finally:
        manager.unload()


def test_unrelated_registration_failure_is_not_suppressed(tmp_path, monkeypatch):
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
    from secure_env_ingress.plugin import register
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr('hermes_cli.plugins.load_config_readonly', lambda: {})
    manager = PluginManager(scope_key=str(tmp_path))
    ctx = PluginContext(PluginManifest(name='secure-env-ingress', version='test'), manager)
    def broken(**kwargs):
        raise RuntimeError('registration failure')
    monkeypatch.setattr(ctx, 'register_tool', broken)
    with pytest.raises(RuntimeError, match='registration failure'):
        register(ctx)
