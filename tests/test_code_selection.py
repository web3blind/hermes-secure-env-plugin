from types import SimpleNamespace
import json
import pytest
from dataclasses import dataclass
from secure_env_ingress import code_targets as c


@dataclass(frozen=True)
class ExplicitFixtureTarget(c.CodeTarget):
    parent: str = 'p'
    frame: str = 'fixture-frame'
    ancestry: tuple = ()
    explicit_parent: bool = True


def target(page='A', form=0):
    return ExplicitFixtureTarget('https://example.test', 'Fixture', 'task', page, 'nonce',
        'https://example.test/login/private-token?secret=hidden#hidden',
        (SimpleNamespace(control=SimpleNamespace(form_index=form)),), object())


def test_single_auto_multiple_model_choices_and_no_private_metadata(monkeypatch):
    picker = c.CodeSelection()
    monkeypatch.setattr(c, 'discover', lambda *a, **k: [target()])
    chosen, response = picker.choose(('home', 'owner', 'session'), 'https://example.test', 'Fixture', 'task', parent='p')
    assert chosen.page == 'A' and response is None
    monkeypatch.setattr(c, 'discover', lambda *a, **k: [target(), target('B')])
    chosen, response = picker.choose(('home', 'owner', 'session'), 'https://example.test', 'Fixture', 'task', parent='p')
    assert chosen is None and response['status'] == 'selection_required'
    assert len(response['candidates']) == 2
    assert 'private-token' not in json.dumps(response) and 'hidden' not in json.dumps(response)
    token = response['candidates'][1]['selection']
    monkeypatch.setattr(c, 'assert_target', lambda t: None)
    with pytest.raises(ValueError):
        picker.choose(('other-home', 'owner', 'session'), 'https://example.test', 'Fixture', 'task', token, parent='p')
    with pytest.raises(ValueError):
        picker.choose(('home', 'owner', 'session'), 'https://wrong.test', 'Fixture', 'task', token, parent='p')
    chosen, response = picker.choose(('home', 'owner', 'session'), 'https://example.test', 'Fixture', 'task', token, parent='p')
    assert chosen.page == 'B' and response is None
    with pytest.raises(ValueError):
        picker.choose(('home', 'owner', 'session'), 'https://example.test', 'Fixture', 'task', token, parent='p')


def test_expired_choice_and_disappeared_page_do_not_retarget(monkeypatch):
    monkeypatch.setattr(c, 'discover', lambda *a, **k: [target(), target('B')])
    monkeypatch.setattr(c.time, 'monotonic', lambda: 10)
    picker = c.CodeSelection()
    _, response = picker.choose(('scope',), 'https://example.test', 'Fixture', 'task', parent='p')
    token = response['candidates'][0]['selection']
    monkeypatch.setattr(c.time, 'monotonic', lambda: 131)
    with pytest.raises(ValueError):
        picker.choose(('scope',), 'https://example.test', 'Fixture', 'task', token, parent='p')
    _, response = picker.choose(('scope',), 'https://example.test', 'Fixture', 'task', parent='p')
    monkeypatch.setattr(c, 'assert_target', lambda t: (_ for _ in ()).throw(ValueError('gone')))
    with pytest.raises(ValueError, match='gone'):
        picker.choose(('scope',), 'https://example.test', 'Fixture', 'task', response['candidates'][0]['selection'], parent='p')


def test_no_form_does_not_request_secret(monkeypatch):
    monkeypatch.setattr(c, 'discover', lambda *a, **k: [])
    target, response = c.CodeSelection().choose(('scope',), 'https://example.test', 'Fixture', 'task', parent='p')
    assert target is None and response['status'] == 'no_code_form'
