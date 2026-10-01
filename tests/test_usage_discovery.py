"""Discover both secret-entry modes and the bundled skill via real registration."""
import json

from generic_helpers import registered
from gateway.run import _profile_runtime_scope
from test_runtime_e2e import make_runtime
from tools.registry import registry
from tools.skills_tool import skill_view


def test_registered_usage_and_both_modes(tmp_path, monkeypatch):
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        entry = registry.get_entry('browser_vault', scope=str(home))
        description = entry.schema['description'].lower()
        for term in ('secure env', 'login', 'username', 'password', 'code', 'passcode', 'payment', 'confirmation', 'prompt_unavailable'):
            assert term in description
        assert set(entry.schema['parameters']['properties']['mode']['enum']) == {'login', 'code', 'payment'}
        assert 'mode' not in entry.schema['parameters']['required']
        result = json.loads(skill_view('secure-env-ingress:usage'))
        assert result['success'], result
        assert result['content']
