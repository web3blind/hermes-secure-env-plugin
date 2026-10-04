import pytest
from secure_env_ingress.code_targets import _classified

@pytest.mark.parametrize('label', ['Введите код подтверждения', 'Одноразовый код', 'Код верификации', 'Код из SMS', 'Login verification code', 'Email verification code'])
def test_russian_verification(label):
    assert len(_classified([dict(index=0, name='Code', label=label, type='text')])) == 1

@pytest.mark.parametrize('row', [
    dict(name='code', label='Code', type='text'),
    dict(name='code', label='Промокод подтверждения', type='text'),
    dict(name='password', label='Введите код подтверждения', type='password'),
    dict(name='cvv', label='Verification code', type='text'),
    dict(name='code', label='Код подтверждения', type='hidden'),
])
def test_non_otp_refused(row):
    assert not _classified([dict(index=0, **row)])


@pytest.mark.parametrize('explicit', [False, True])
@pytest.mark.parametrize('autocomplete,allowed', [
    ('section-login one-time-code', True),
    ('section-a42 one-time-code', True),
    ('section-login current-password', False),
    ('section-login new-password', False),
    ('section-login cc-csc', False),
    ('section-login one-time-code current-password', False),
    ('one-time-code section-login', False),
    ('section- one-time-code', False),
    ('section-login section-other one-time-code', False),
])
def test_sectioned_otp_semantics(explicit, autocomplete, allowed):
    row = dict(index=0, name='otp', label='Verification code', type='text',
               autocomplete=autocomplete, selected=True)
    assert bool(_classified([row], explicit=explicit)) is allowed

@pytest.mark.parametrize('selector,parent', [(None, None), ('#code', 'parent')])
def test_locator_valid(selector, parent):
    from secure_env_ingress.code_targets import validate_field_selector
    validate_field_selector(selector, parent)

@pytest.mark.parametrize('selector,parent', [('', 'p'), ('a'*257, 'p'), ('#code', None), ('#code', ''), (False, 'p'), (12, 'p'), ('a\n', 'p')])
def test_locator_invalid(selector, parent):
    from secure_env_ingress.code_targets import validate_field_selector
    with pytest.raises(ValueError):
        validate_field_selector(selector, parent)

@pytest.mark.parametrize('mode,selector,parent', [
    ('login', '#code', 'p'), ('payment', '#code', 'p'), ('code', '#code', None),
    ('code', None, 'p'), ('code', '', 'p'), ('code', False, 'p'), ('code', 'a'*257, 'p'),
])
def test_registered_invalid_locator_no_discovery(tmp_path, monkeypatch, mode, selector, parent):
    import json
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress.code_targets import CodeSelection
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr(CodeSelection, 'choose', lambda *a, **k: pytest.fail('invalid input reached discovery'))
    with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
        entry = registry.get_entry('browser_vault', scope=str(home))
        assert entry.schema['parameters']['properties']['field_selector']['maxLength'] == 256
        result = json.loads(registry.dispatch('browser_vault', dict(origin='https://synthetic.test', label='Synthetic', mode=mode, field_selector=selector, **({'parent':parent} if parent is not None else {})), task_id='synthetic'))
        assert result['success'] is False and result['reason'] == 'session_binding'


def test_selection_cannot_change_selector_lineage(monkeypatch):
    from types import SimpleNamespace
    from secure_env_ingress import code_targets as codes
    def target(page):
        return SimpleNamespace(task='task', parent='p', field_selector=None, origin='https://synthetic.test', label='Synthetic', href='https://synthetic.test/verify', page=page, frame='f', ancestry=(), controls=(SimpleNamespace(control=SimpleNamespace(form_index=0)),))
    monkeypatch.setattr(codes, 'discover', lambda *a, **k: [target('a'), target('b')])
    monkeypatch.setattr(codes, 'release', lambda *a: None)
    picker = codes.CodeSelection()
    try:
        _, response = picker.choose(('scope',), 'https://synthetic.test', 'Synthetic', 'task', parent='p')
        with pytest.raises(ValueError):
            picker.choose(('scope',), 'https://synthetic.test', 'Synthetic', 'task', response['candidates'][0]['selection'], 'p', '#code')
    finally:
        picker.close()
