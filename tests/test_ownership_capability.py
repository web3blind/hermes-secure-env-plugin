"""Tab creation history is not an authorization capability in 0.8.3."""
import builtins
from test_parent_transport import transport as _transport
from secure_env_ingress.parent_session import ParentSession

transport = _transport


def test_absent_ownership_surface_does_not_affect_exact_admission(transport, monkeypatch, tmp_path):
    host, _, _, sessions = transport
    original = builtins.__import__
    def gated_import(name, *args, **kwargs):
        if name == 'tools.browser_tab_lifecycle':
            raise AssertionError('removed ownership module must not be imported')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', gated_import)
    parent = ParentSession(host.handle, 'parent')
    try:
        assert parent.check() == parent.sid
        assert sessions[parent.sid] == 'parent'
    finally:
        parent.drop(None)
    assert not (tmp_path / 'browser_tabs.sqlite').exists()
