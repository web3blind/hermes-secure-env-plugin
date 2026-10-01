"""Standalone code ingress through real HTTPS and native classifier/CDP expression."""
import json
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from test_runtime_e2e import make_runtime, post
from secure_env_ingress.vault_ingress import capture_browser_target


@pytest.fixture
def harness(tmp_path, monkeypatch):
    from tools import browser_use_cli, browser_supervisor
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr(browser_use_cli, 'is_browser_use_cli_mode', lambda: True)
    scripts = []
    state = {'href': 'https://site.test/challenge', 'page': 'page', 'controls': [{
        'autocomplete': 'one-time-code', 'formIndex': 0, 'index': 0, 'maxLength': 8,
        'label': 'Verification code', 'name': 'verification_code', 'type': 'text'}]}
    supervisor = SimpleNamespace(task_id='task', _state_lock=threading.RLock(),
                                 _active=True, _page_session_id='page')

    def evaluate(expr):
        if expr == 'location.href':
            return {'ok': True, 'result': state['href']}
        scripts.append(expr)
        if 'const expectedOrigin' in expr:
            if state['href'].split('/')[2] != 'site.test':
                return {'ok': True, 'result': json.dumps({'refused': 'origin_changed'})}
            return {'ok': True, 'result': json.dumps({'filled': state.get('filled', 1)})}
        return {'ok': True, 'result': json.dumps(state['controls'])}

    supervisor.evaluate_runtime = evaluate
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    target = capture_browser_target('https://site.test', 'Synthetic challenge', 'task', 'task', 'chat-key')
    yield runtime, cfg, home, root, target, state, scripts, supervisor
    runtime.close()


def issue(harness):
    runtime = harness[0]
    links = runtime.create_vault(('telegram', '7'), harness[4], mode='code')
    return links, urlsplit(links['url']).fragment


@pytest.mark.parametrize('code', ['A1B2C3', 'Q!7&z=R9', '\"Q7\\\\z\'R9'])
def test_https_code_fill_no_vault_replay_and_no_echo(harness, caplog, code):
    runtime, cfg, home, root, target, state, scripts, _ = harness
    state['controls'][0]['maxLength'] = 16
    links, token = issue(harness)
    status, form = post(cfg, root, '/session', {'token': token, 'initData': ''})
    assert status == 200 and form['kind'] == 'browser_code' and form['keys'] == ['Verification code']
    status, result = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': [code]})
    assert (status, result) == (200, {'filled': True})
    assert links['completion'].result(timeout=1) == {'status': 'filled', 'origin': target.origin}
    assert len(scripts) == 2 and code not in scripts[0] and json.dumps(code) in scripts[1]
    assert target.origin in scripts[1]
    assert post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': [code]})[0] == 410
    assert not (home / 'vault').exists() and not (home / '.env').exists()
    assert code not in caplog.text and code not in json.dumps(result)


@pytest.mark.parametrize('maximum,expected', [(-1, 200), (None, 200), (6, 200), (5, 409), (0, 409)])
def test_google_style_code_field_length(harness, maximum, expected):
    _, cfg, _, root, _, state, _, _ = harness
    state['controls'][0].update(type='tel', name='code', autocomplete='',
                                label='Введите код', maxLength=maximum)
    links, token = issue(harness)
    status, result = post(cfg, root, '/submit', {
        'token': token, 'initData': '', 'values': ['A1B2C3']})
    assert status == expected
    if expected == 200:
        assert result == {'filled': True}
        assert links['completion'].result(timeout=1)['status'] == 'filled'


@pytest.mark.parametrize('name,label,duplicate', [
    ('postal_code', 'Postal code', False), ('promo_code', 'Promo code', False),
    ('code', 'Unrelated value', False), ('code', 'Введите код', True),
])
def test_localized_code_fallback_does_not_guess(harness, name, label, duplicate):
    _, cfg, _, root, _, state, scripts, _ = harness
    state['controls'][0].update(type='tel', name=name, label=label, autocomplete='')
    if duplicate:
        state['controls'].append(dict(state['controls'][0], index=1))
    _, token = issue(harness)
    assert post(cfg, root, '/submit', {
        'token': token, 'initData': '', 'values': ['A1B2C3']})[0] == 409
    assert not any('const expectedOrigin' in script for script in scripts)


@pytest.mark.parametrize('case,expected', [
    ('invalid', 400), ('no_field', 409), ('ambiguous', 409),
    ('origin', 409), ('page', 409), ('partial', 409),
])
def test_fail_closed_code_submission(harness, case, expected):
    runtime, cfg, home, root, target, state, scripts, supervisor = harness
    links, token = issue(harness)
    code = 'A1B2C3'
    if case == 'invalid':
        code = '123'
    if case == 'no_field':
        state['controls'] = []
    if case == 'ambiguous':
        state['controls'].append(dict(state['controls'][0], index=2))
    if case == 'origin':
        state['href'] = 'https://else.test/challenge'
    if case == 'page':
        supervisor._page_session_id = 'new-page'
    if case == 'partial':
        state['filled'] = 0
    status, result = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': [code]})
    assert status == expected and 'filled' not in result
    assert links['completion'].result(timeout=1)['status'] in ('rejected', 'failed', 'unknown')
    assert post(cfg, root, '/session', {'token': token, 'initData': ''})[0] == 410
    assert not (home / 'vault').exists()
    if case != 'partial':
        assert not any('const expectedOrigin' in script for script in scripts)


@pytest.mark.parametrize('code', ['abc', 'a' * 17, 'ab cd', 'abcd\n', 'ab\x00cd', 'абвг'])
def test_invalid_code_characters_rejected(harness, code):
    _, cfg, _, root, _, _, scripts, _ = harness
    _, token = issue(harness)
    status, _ = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': [code]})
    assert status == 400
    assert not scripts


def test_cancel_before_submission(harness):
    runtime, cfg, _home, root, _target, _state, scripts, _supervisor = harness
    links, token = issue(harness)
    runtime.cancel_group(links['group_id'])
    assert links['completion'].result(timeout=1)['status'] == 'cancelled'
    assert runtime._store.peek(token) is None
    assert not scripts


def test_page_changes_during_inspection_are_refused(harness):
    runtime, cfg, _home, root, _target, state, scripts, supervisor = harness
    _links, token = issue(harness)
    original = supervisor.evaluate_runtime

    def switched(expr):
        result = original(expr)
        if expr != 'location.href' and 'const expectedOrigin' not in expr:
            supervisor._page_session_id = 'different-page'
        return result

    supervisor.evaluate_runtime = switched
    status, _ = post(cfg, root, '/submit', {'token': token, 'initData': '', 'values': ['A1B2C3']})
    assert status == 409 and len(scripts) == 1


def test_split_code_boxes_are_filled_only_when_exact(harness):
    runtime, cfg, _home, root, _target, state, scripts, _supervisor = harness
    state['controls'] = [dict(state['controls'][0], index=index, maxLength=1)
                         for index in range(6)]
    state['filled'] = 6
    _links, token = issue(harness)
    status, result = post(cfg, root, '/submit',
                          {'token': token, 'initData': '', 'values': ['A1B2C3']})
    assert (status, result) == (200, {'filled': True})
    assert len(scripts) == 2 and scripts[1].count('"one-time-code"') == 6


def test_expired_after_inspection_refuses_fill(harness, monkeypatch):
    from secure_env_ingress import vault_ingress
    runtime, cfg, _home, root, _target, _state, scripts, _supervisor = harness
    links, token = issue(harness)
    original_clock = vault_ingress.time.monotonic
    monkeypatch.setattr(vault_ingress, 'time', SimpleNamespace(
        monotonic=lambda: links['expires_at'] + 1 if scripts else original_clock()))
    status, _ = post(cfg, root, '/submit',
                     {'token': token, 'initData': '', 'values': ['A1B2C3']})
    assert status == 409 and len(scripts) == 1
