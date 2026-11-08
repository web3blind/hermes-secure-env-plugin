"""Real Chromium declared-card traversal regression; synthetic native consent."""
import pytest
from test_nested_code import nested as chromium_fixture
from exact_card_helpers import page, registered_fill

nested = chromium_fixture


@pytest.mark.parametrize('topology', ['top', 'shadow', 'closed', 'multi'])
def test_explicit_card_stops_after_declared_destinations(nested, tmp_path, monkeypatch, topology):
    origin, _leaf, spec = page(nested, topology=topology)
    if topology == 'top':
        spec['fields'] = spec['fields'][:1]
    # The last destination has unrelated service frames. A trailing sibling
    # proves the enclosing parent's loop stops after the last declared field.
    frames = [nested.page] if topology == 'top' else [f for f in nested.page.frames if f.url.startswith(origin + '/')]
    for frame in frames[-1:]:
        frame.evaluate('()=>{for(let i=0;i<21;i++)document.body.append(document.createElement("iframe"))}')
    if topology != 'top':
        nested.page.evaluate('()=>{const f=document.createElement("iframe");f.srcdoc="<iframe></iframe>".repeat(21);document.body.append(f)}')
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, spec)
    assert result['status'] == 'filled', result
    assert result['filled_fields'] == len(spec['fields'])
    assert len(seen) == len(resolved) == 1
    assert all(f.evaluate('!window.clicked&&!window.submitted') for f in frames)



