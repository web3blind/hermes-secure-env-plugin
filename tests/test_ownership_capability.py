"""Absent optional ownership APIs refuse without requesting a config change."""
import builtins
from pathlib import Path
import pytest
from secure_env_ingress.parent_session import _proof
from secure_env_ingress.code_targets import binding_failure_detail


def test_absent_ownership_surface_has_fixed_safe_refusal(monkeypatch, tmp_path):
    original = builtins.__import__
    def gated_import(name, *args, **kwargs):
        if name == 'tools.browser_tab_lifecycle':
            raise ModuleNotFoundError('fixture missing feature', name=name)
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', gated_import)
    with pytest.raises(ValueError, match='^parent ownership unavailable$') as result:
        _proof('fixture-task', 'ws://127.0.0.1/devtools/browser/fixture', 'fixture-parent', Path(tmp_path))
    assert binding_failure_detail(result.value) == 'parent_ownership'
    assert not (tmp_path / 'browser_tabs.sqlite').exists()
