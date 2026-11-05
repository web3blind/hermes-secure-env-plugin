"""Exact public SDK values may cross the directory-loader boundary, not registries."""
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from secure_env_ingress import operations as sdk


@pytest.fixture
def isolated(monkeypatch):
    name = 'synthetic_directory_operations'
    spec = importlib.util.spec_from_file_location(name, Path(sdk.__file__))
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('bad', ['lookalike', 'subclass', 'callback', 'coroutine',
                                 'blank', 'control', 'large'])
def test_public_sdk_does_not_widen_validation(tmp_path, isolated, bad):
    def callback(secret):
        raise AssertionError('binding must never execute a callback')
    async def asynchronous(secret):
        pass
    class Derived(sdk.BoundOperation):
        pass
    value = {
        'lookalike': SimpleNamespace(summary='Synthetic', execute=callback),
        'subclass': Derived('Synthetic', callback),
        'callback': sdk.BoundOperation('Synthetic', None),
        'coroutine': sdk.BoundOperation('Synthetic', asynchronous),
        'blank': sdk.BoundOperation(' ', callback),
        'control': sdk.BoundOperation('Synthetic\n', callback),
        'large': sdk.BoundOperation('x' * 769, callback),
    }[bad]
    isolated.register_consumer(tmp_path, 'synthetic', lambda raw: value)
    with pytest.raises(ValueError, match='invalid bound operation'):
        isolated.bind(tmp_path, 'synthetic', {})


def test_current_exact_sdk_normalizes_without_running_callback(tmp_path, isolated):
    seen = []
    value = sdk.BoundOperation('x' * 768, seen.append)
    isolated.register_consumer(tmp_path, 'synthetic', lambda raw: value)
    bound, canonical = isolated.bind(tmp_path, 'synthetic', {'b': 2, 'a': 1})
    assert type(bound) is isolated.BoundOperation
    assert bound.execute is value.execute
    assert canonical == b'{"a":1,"b":2}' and seen == []
    bound.execute('synthetic')
    assert seen == ['synthetic']
    with pytest.raises(ValueError):
        sdk.bind(tmp_path, 'synthetic', {})


def test_missing_sdk_keeps_local_consumers_and_rejects_old_public_values(tmp_path, isolated, monkeypatch):
    value = sdk.BoundOperation('Synthetic', lambda secret: None)
    monkeypatch.delitem(sys.modules, 'secure_env_ingress.operations')
    isolated.register_consumer(tmp_path, 'local',
                               lambda raw: isolated.BoundOperation('Local', lambda secret: None))
    isolated.register_consumer(tmp_path, 'public', lambda raw: value)
    assert isolated.bind(tmp_path, 'local', {})[0].summary == 'Local'
    with pytest.raises(ValueError, match='invalid bound operation'):
        isolated.bind(tmp_path, 'public', {})
