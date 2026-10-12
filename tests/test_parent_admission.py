"""Exact parent admission on released public capture, without optional ownership."""
import pytest
from test_parent_transport import transport as _transport
from secure_env_ingress import parent_session as ps

transport = _transport


@pytest.mark.parametrize('info', [
    {'targetId': 'other', 'type': 'page', 'url': 'http://merchant.test/checkout'},
    {'targetId': 'other', 'type': 'iframe', 'url': 'https://merchant.test/checkout'},
    {'targetId': 'other', 'type': 'page', 'url': 'https://user:password@merchant.test/checkout'},
])
def test_default_matching_parent_invalid_admission(transport, monkeypatch, info):
    host, _, _, _ = transport
    original = ps._call
    def call(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[1] == 'Target.getTargetInfo':
            return {'result': {'targetInfo': info}}
        return result
    monkeypatch.setattr(ps, '_call', call)
    with pytest.raises(ValueError, match='parent unavailable'):
        ps.ParentSession(host.handle, 'other')


def test_stock_optional_ownership_refuses_without_attachment(transport, monkeypatch, tmp_path):
    host, wire, _, sessions = transport
    # Remove only the fixture's proof override, not any real host API.
    monkeypatch.setattr(ps, '_proof', STOCK_PROOF)
    with pytest.raises(ValueError, match='parent ownership unavailable'):
        ps.ParentSession(host.handle, 'parent')
    assert not any(c['method'] == 'Target.attachToTarget' for c in wire.commands)
    assert set(sessions) == {'default', 'sibling'}
    assert not (tmp_path / 'browser_tabs.sqlite').exists()


STOCK_PROOF = ps._proof
