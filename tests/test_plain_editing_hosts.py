"""Plain editing hosts: exact text reflection, no markup adoption or guessing."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes
from exact_card_helpers import page, registered_fill, mutate_js






@pytest.mark.parametrize('markup', ['<b>rich</b>', '<br>', '<!--comment-->'])
def test_card_rich_editor_before_consent_refuses(nested, tmp_path, monkeypatch, markup):
    origin, leaf, target_spec = page(nested, kind='editable')
    leaf.evaluate('(s)=>document.querySelector("#pan").innerHTML=s', markup)
    result, seen, resolved = registered_fill(nested, tmp_path, monkeypatch, origin, target_spec)
    assert result['status'] == 'target_refused'
    assert not seen and not resolved
    assert leaf.evaluate('window.writes===0&&!window.clicked&&!window.submitted')
