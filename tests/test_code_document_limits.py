"""Synthetic document limits and secret-free dispatcher diagnostics."""
import json
import time

import pytest

from secure_env_ingress import code_targets as codes
from test_nested_code import nested as nested, setup_chain

CODE = '<input name="Code" placeholder="Введите код подтверждения">'


def markup(depth):
    return ('<div>' * depth + '<form id="loginForm">' + CODE +
            '</form>' + '</div>' * depth)


@pytest.mark.parametrize('depth', [19, 24])
@pytest.mark.parametrize('explicit', [False, True])
def test_deep_localized_code_fills(nested, depth, explicit):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', markup(depth))
    options = {'field_selector': '#loginForm input[name=Code]'} if explicit else {}
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, **options)[0]
    try:
        assert codes.fill(target, 'A!7&z=R9', time.monotonic()+20)
    finally:
        codes.release(target)


@pytest.mark.parametrize('sites', [('parent.test', 'parent.test'), ('middle.test', 'leaf.test')])
@pytest.mark.parametrize('explicit', [False, True])
def test_registered_deep_https(nested, sites, explicit, tmp_path, monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    run(nested, sites, False, tmp_path, monkeypatch,
        field_selector='#loginForm input[name=Code]' if explicit else None,
        markup=markup(19))


@pytest.mark.parametrize('attack', [
    'document.querySelector("input").replaceWith(document.querySelector("input").cloneNode())',
    'history.replaceState({},"","/other");history.replaceState({},"","/leaf")',
])
def test_deep_document_keeps_sticky_guards(nested, attack):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', markup(19))
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate(attack)
        with pytest.raises(ValueError):
            codes.fill(target, 'A!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("input").value === ""')
    finally:
        codes.release(target)


@pytest.mark.parametrize('case,detail', [
    ('depth', 'document_depth'), ('nodes', 'document_capacity'),
])
def test_document_bounds_still_refuse(nested, case, detail):
    origin, leaf = setup_chain(nested)
    html = markup(140) if case == 'depth' else markup(0)
    if case == 'nodes':
        html += '<span></span>' * 10100
    leaf.evaluate('(html)=>document.body.innerHTML=html', html)
    with pytest.raises(ValueError) as caught:
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)
    assert codes.binding_failure_detail(caught.value) == detail
    assert leaf.evaluate('document.querySelector("input").value === ""')


def test_hidden_duplicate_requires_unique_selector(nested):
    origin, leaf = setup_chain(nested)
    html = ('<section hidden><form id="loginForm">' + CODE + '</form></section>' +
            '<section id="active-challenge">' + markup(19) + '</section>')
    leaf.evaluate('(html)=>document.body.innerHTML=html', html)
    with pytest.raises(ValueError, match='ambiguous code selector'):
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent,
                       field_selector='#loginForm input[name=Code]')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent,
                            field_selector='#active-challenge input[name=Code]')[0]
    try:
        assert codes.fill(target, 'A!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("section[hidden] input").value === ""')
    finally:
        codes.release(target)


@pytest.mark.parametrize('case,detail', [
    ('depth', 'document_depth'), ('duplicate', 'selector_ambiguous'),
])
def test_registered_real_discovery_details(nested, tmp_path, monkeypatch, case, detail):
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry

    setup_chain(nested)
    html = markup(140) if case == 'depth' else (
        '<section hidden>' + markup(0) + '</section>' + markup(0))
    nested.page.evaluate('(html)=>document.body.innerHTML=html', html)
    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    settings['allowed_telegram_user_ids'] = [7]
    task = nested.sup.task_id
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
            chat_type='group', session_id=task, session_key='key', cron_session='')
        try:
            raw = registry.dispatch('browser_vault',
                {'origin': 'https://parent.test', 'label': 'Fixture', 'mode': 'code',
                 'parent': nested.parent, 'field_selector': '#loginForm input[name=Code]'},
                task_id=task, session_id=task)
        finally:
            sc.clear_session_vars(tokens)
    result = json.loads(raw)
    assert result['reason'] == 'browser_binding' and result['detail'] == detail
    assert 'https://parent.test' not in raw and '#loginForm' not in raw
    assert nested.page.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')


@pytest.mark.parametrize('message,detail', [
    ('unsupported document depth', 'document_depth'),
    ('unsupported document capacity', 'document_capacity'),
    ('unsupported shadow', 'document_shadow'),
    ('ambiguous code selector', 'selector_ambiguous'),
    ('inadmissible code selector', 'selector_inadmissible'),
    ('explicit parent not owned by task', 'parent_ownership'),
    ('code document changed', 'target_changed'),
    ('SECRET_PAGE_TEXT https://untrusted.test/?token=PRIVATE', 'binding_refused'),
])
def test_registered_safe_binding_detail(tmp_path, monkeypatch, message, detail):
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry

    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    settings['allowed_telegram_user_ids'] = [7]
    def refuse(*args, **kwargs):
        raise ValueError(message)
    monkeypatch.setattr(codes.CodeSelection, 'choose', refuse)
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
            chat_type='group', session_id='sid', session_key='key', cron_session='')
        try:
            raw = registry.dispatch('browser_vault',
                {'origin': 'https://site.test', 'label': 'Fixture', 'mode': 'code'},
                task_id='sid', session_id='sid')
        finally:
            sc.clear_session_vars(tokens)
    result = json.loads(raw)
    assert result['success'] is False and result['reason'] == 'browser_binding'
    assert result['detail'] == detail
    assert message not in raw and 'https://site.test' not in raw
    assert 'SECRET_PAGE_TEXT' not in raw and 'PRIVATE' not in raw
