"""Strong code/credential evidence must refuse before native card approval."""
import pytest
from test_nested_code import nested as nested
from exact_card_helpers import page, registered_fill


@pytest.mark.parametrize('kind', ['input', 'editable'])
@pytest.mark.parametrize('evidence', ['oneTimeCode', 'passwordInput', 'Email verification code', 'One-time password', 'Код подтверждения', 'Одноразовый пароль', 'apiKey', 'userName', 'email'])
def test_native_card_purpose_before_approval(nested, tmp_path, monkeypatch, kind, evidence):
    origin, leaf, target = page(nested, kind=kind)
    leaf.evaluate('s=>document.querySelector("#pan").setAttribute("aria-label",s)', evidence)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target)
    assert result['status'] == 'target_refused', result
    assert not seen and not resolved
    assert leaf.evaluate('window.writes===0&&!window.clicked&&!window.submitted')


@pytest.mark.parametrize('autocomplete,allowed', [
    ('one-time-code cc-number', False),
    ('current-password cc-number', False),
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
@pytest.mark.parametrize('attribute', ['name', 'id', 'aria-label', 'title', 'placeholder'])
@pytest.mark.parametrize('evidence', ['Access token', 'Bearer token', 'Refresh token', 'Auth token', 'JWT', 'accessToken', 'bearerToken', 'refreshToken', 'authToken', 'jwtToken'])
def test_token_conflict_before_approval(nested, tmp_path, monkeypatch, kind, attribute, evidence):
    origin, leaf, target = page(nested, kind=kind)
    # Keep the selector in the supported simple-ID grammar so refusal proves
    # purpose admission, not an unrelated unsupported-selector rejection.
    value = evidence.replace(' ', '') if attribute == 'id' else evidence
    leaf.evaluate('([attribute,evidence])=>document.querySelector("#pan").setAttribute(attribute,evidence)', [attribute, value])
    if attribute == 'id':
        target['fields'][0]['selector'] = '#' + value
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target)
    assert result['status'] == 'target_refused', result
    assert not seen and not resolved
    assert leaf.evaluate('window.writes===0&&!window.clicked&&!window.submitted')


@pytest.mark.parametrize('kind', ['input', 'editable'])
@pytest.mark.parametrize('cvc_label', ['CVC', 'Security code', 'Card security code'])
def test_card_roles_remain_allowed(nested, tmp_path, monkeypatch, kind, cvc_label):
    origin, leaf, target = page(nested, kind=kind)
    leaf.evaluate('label=>{document.querySelector("#pan").setAttribute("aria-label","Card number");document.querySelector("#cvc").setAttribute("aria-label",label);for(const [id,ac] of [["pan","cc-number"],["holder","cc-name"],["exp","cc-exp"],["cvc","cc-csc"]])document.getElementById(id).setAttribute("autocomplete","section-checkout billing "+ac)}', cvc_label)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target)
    assert result['status'] == 'filled', result
    assert len(seen) == len(resolved) == 1
    assert leaf.evaluate('window.writes===4&&!window.clicked&&!window.submitted')
