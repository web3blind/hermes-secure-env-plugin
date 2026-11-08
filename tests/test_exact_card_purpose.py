"""Strong code/credential evidence must refuse before native card approval."""
import pytest
from test_nested_code import nested as nested
from exact_card_helpers import page, registered_fill




@pytest.mark.parametrize('autocomplete,allowed', [
    ('one-time-code cc-number', True),
    ('current-password cc-number', True),
    ('section-checkout billing cc-number', True),
    ('SECTION-CHECKOUT BILLING CC-NUMBER', True),
])
def test_card_autocomplete_complete_role(nested, tmp_path, monkeypatch, autocomplete, allowed):
    origin, leaf, target = page(nested)
    leaf.evaluate('s=>document.querySelector("#pan").setAttribute("autocomplete",s)', autocomplete)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target)
    assert result['status'] == ('filled' if allowed else 'target_refused'), result
    assert bool(seen) == bool(resolved) == allowed
    assert leaf.evaluate('!window.clicked&&!window.submitted')
    assert leaf.evaluate('window.writes') == (4 if allowed else 0)




@pytest.mark.parametrize('kind', ['input', 'editable'])
@pytest.mark.parametrize('cvc_label', ['CVC', 'Security code', 'Card security code'])
def test_card_roles_remain_allowed(nested, tmp_path, monkeypatch, kind, cvc_label):
    origin, leaf, target = page(nested, kind=kind)
    leaf.evaluate('label=>{document.querySelector("#pan").setAttribute("aria-label","Card number");document.querySelector("#cvc").setAttribute("aria-label",label);for(const [id,ac] of [["pan","cc-number"],["holder","cc-name"],["exp","cc-exp"],["cvc","cc-csc"]])document.getElementById(id).setAttribute("autocomplete","section-checkout billing "+ac)}', cvc_label)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target)
    assert result['status'] == 'filled', result
    assert len(seen) == len(resolved) == 1
    assert leaf.evaluate('window.writes===4&&!window.clicked&&!window.submitted')
