"""Closed intent/policy behavior; no source-shape assertions."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from secure_env_ingress.exact_code import validate_spec, descriptor, validate_descriptor, policy
from secure_env_ingress.server import _Handler, HTTPError
from test_exact_code_browser import spec


@pytest.mark.parametrize('n', [1, 2, 3, 16, 17, 99, 100])
def test_lengths_and_descriptor(n):
    s = validate_spec(spec(n), 'owned')
    assert policy(s).accepts('!' * n)
    assert not policy(s).accepts('!' * (n+1))
    assert validate_descriptor(descriptor(s)) == descriptor(s)
    original = spec(n)
    frozen = validate_spec(original, 'owned')
    original['validation']['exact_length'] = 99
    assert frozen == s


@pytest.mark.parametrize('change', [
    {'version': True}, {'version': 2}, {'purpose': 'password'}, {'layout': 'javascript'},
    {'extra': 'arbitrary'}, {'fields': []}, {'fields': [{'selector': '#x', 'value': 'forbidden'}]},
    {'fields': [{'selector': 'x\n'}]}, {'fields': [{'selector': 'x'*257}]},
    {'validation': {'charset': 'regex', 'exact_length': 1, 'multiline': False}},
    {'validation': {'charset': 'ascii_digits', 'exact_length': True, 'multiline': False}},
    {'validation': {'charset': 'ascii_digits', 'exact_length': 101, 'multiline': False}},
    {'validation': {'charset': 'ascii_digits', 'exact_length': 1, 'multiline': True}},
    {'validation': {'charset': 'unicode_text', 'exact_length': 1, 'multiline': 'true'}},
])
def test_closed_spec(change):
    s = spec()
    s.update(deepcopy(change))
    with pytest.raises(ValueError):
        validate_spec(s, 'owned')


@pytest.mark.parametrize('parent', [None, '', True, 1])
def test_parent_required(parent):
    with pytest.raises(ValueError):
        validate_spec(spec(), parent)


@pytest.mark.parametrize('layout', ['ordered_cells', 'indexed_cells'])
def test_group_mismatch(layout):
    s = spec(100, layout)
    s['validation']['exact_length'] = 99
    with pytest.raises(ValueError):
        validate_spec(s, 'owned')


@pytest.mark.parametrize('value', ['A\rB', 'A\x00B', 'A\u200bB', 'A\ud800B', 'A\tB', 'A\u2028B', 'A\u2029B'])
def test_unicode_controls_rejected(value):
    assert not policy(spec(len(value), multiline=True)).accepts(value)


def test_lf_is_only_explicit_unicode_multiline():
    s = spec(4, multiline=True)
    assert policy(s).accepts('A\nБ🙂')
    s['validation']['multiline'] = False
    assert not policy(s).accepts('A\nБ🙂')
    h = object.__new__(_Handler)
    h.server = SimpleNamespace(max_values=64, max_value_bytes=16384)
    for value in ['A\nB', 'A\rB', 'A\x00B']:
        with pytest.raises(HTTPError):
            h._validate_values([value])
    assert h._validate_values(['A\nB'], allow_lf=True) == ['A\nB']
    for value in ['A\rB', 'A\x00B']:
        with pytest.raises(HTTPError):
            h._validate_values([value], allow_lf=True)


@pytest.mark.parametrize('count', [0, 101, True])
def test_descriptor_count_closed(count):
    d = descriptor(spec())
    d['count'] = count
    with pytest.raises(ValueError):
        validate_descriptor(d)


@pytest.mark.parametrize('tool,mode', [('secure_env_vault', 'login'), ('secure_env_vault', 'payment'), ('secure_payment_fill', None)])
def test_exact_card_or_login_payload_is_not_accepted(tmp_path, monkeypatch, tool, mode):
    import json
    from generic_helpers import registered
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from test_runtime_e2e import make_runtime
    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    calls = []
    monkeypatch.setattr('secure_env_ingress.code_targets.discover', lambda *a, **kw: calls.append('discover'))
    with registered(monkeypatch, home, settings=settings) as (_, gateway):
        with _profile_runtime_scope(home, {}):
            tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600', session_id='sid', session_key='key', cron_session='')
            try:
                args = {'origin': 'https://site.test', 'label': 'Fixture', 'target_spec': spec()}
                if mode is not None:
                    args['mode'] = mode
                else:
                    args.update(handle='synthetic-handle', parent='task-owned')
                result = json.loads(registry.dispatch(tool, args, task_id='sid', session_id='sid'))
            finally:
                sc.clear_session_vars(tokens)
        assert result['success'] is False
        assert not gateway.sent and not calls
        assert not (home/'vault').exists() and not (home/'.env').exists()


@pytest.mark.parametrize('mode', ['env', 'login', 'payment'])
@pytest.mark.parametrize('confirmed', [None, True])
def test_explicit_lf_exception_never_leaks_into_legacy_modes(tmp_path, monkeypatch, mode, confirmed):
    from urllib.parse import urlsplit
    from test_runtime_e2e import make_runtime, post
    from secure_env_ingress.vault_ingress import capture_login_target
    from test_payment_ingress import card_values
    runtime, cfg, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    try:
        if mode == 'env':
            links = runtime.create(7, 'service')
            values = ['synthetic\nfixture']
        else:
            links = runtime.create_vault(('telegram', '7'), capture_login_target('https://site.test', 'Fixture', 'task', 'key'), mode=mode)
            values = ['synthetic-user', 'synthetic\nfixture'] if mode == 'login' else card_values()
            if mode == 'payment':
                values[1] = 'synthetic\nfixture'
        payload = {'token': urlsplit(links['url']).fragment, 'initData': '', 'values': values}
        if confirmed is not None:
            payload['confirmed'] = confirmed
        status, body = post(cfg, root, '/submit', payload)
        assert (status, body) == (400, {'error': 'invalid_request'})
        if mode != 'env':
            assert links['completion'].result(2)['status'] == 'rejected'
        assert not (home/'vault'/'vault.json.enc').exists() and not (home/'.env').exists()
    finally:
        runtime.close()
