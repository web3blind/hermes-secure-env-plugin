"""Imported local redaction policy, including conservative old-host support."""
from types import SimpleNamespace
import pytest
from secure_env_ingress.redaction_compat import register_context_secret

@pytest.mark.parametrize('kind', ['otp', 'cvc'])
def test_context_registration_current_host(monkeypatch, kind):
    import agent.redact as redact
    calls = []
    monkeypatch.setattr(redact, 'register_vault_redaction_value', lambda value, *, kind='secret': calls.append((value, kind)))
    register_context_secret('synthetic', kind=kind)
    assert calls == [('synthetic', kind)]

@pytest.mark.parametrize('kind', ['otp', 'cvc'])
def test_old_host_conservative_global_fallback(monkeypatch, kind):
    import agent.redact as redact
    calls = []
    monkeypatch.setattr(redact, 'register_vault_redaction_value', lambda value: calls.append(value))
    register_context_secret('synthetic', kind=kind)
    assert calls == ['synthetic']

def test_registration_failure_not_retried_or_skipped(monkeypatch):
    import agent.redact as redact
    calls = []
    def broken(value, *, kind='secret'):
        calls.append(kind)
        raise TypeError('internal failure')
    monkeypatch.setattr(redact, 'register_vault_redaction_value', broken)
    with pytest.raises(TypeError):
        register_context_secret('synthetic', kind='otp')
    assert calls == ['otp']

def test_nested_fill_registers_context_otp(monkeypatch):
    import agent.redact as redact
    from secure_env_ingress import nested_code
    calls = []
    monkeypatch.setattr(redact, 'register_vault_redaction_value', lambda value, *, kind='secret': calls.append((value, kind)))
    with pytest.raises(ValueError):
        nested_code.fill(SimpleNamespace(controls=()), 'synthetic', 0)
    assert calls == [('synthetic', 'otp')]

@pytest.mark.parametrize('old_host', [False, True])
def test_payment_only_pan_and_context_cvc_not_metadata(monkeypatch, old_host):
    import agent.redact as redact
    import tools.browser_vault_tool as native
    from secure_env_ingress import payment_fill as payment
    calls = []
    if old_host:
        def register(value):
            calls.append((value, 'secret'))
    else:
        def register(value, *, kind='secret'):
            calls.append((value, kind))
    monkeypatch.setattr(redact, 'register_vault_redaction_value', register)
    monkeypatch.setattr(native, '_confirm_payment_fill', lambda *a: True)
    meta = SimpleNamespace(label='Synthetic')
    secret = dict(card_number='synthetic-pan', cvc='synthetic-cvc', cardholder_name='Synthetic holder', exp_month='09', exp_year='2031', billing_postal_code='Synthetic postal')
    backend = SimpleNamespace(get_meta=lambda h: meta, resolve_secret=lambda h: dict(secret))
    monkeypatch.setattr(payment, 'payment_backend', lambda *a: backend)
    monkeypatch.setattr(payment, 'assert_target', lambda *a: None)
    monkeypatch.setattr(payment, 'mapped_fills', lambda *a: [])
    monkeypatch.setattr(payment, '_invoke', lambda *a: [])
    target = SimpleNamespace(origin='https://synthetic.test', supervisor=None, child_sid='sid', child_guard='guard', controls=())
    result = payment.approved_fill(target, 'synthetic-handle', lambda: None)
    assert result['status'] == 'filled'
    assert calls == [('synthetic-pan', 'secret'), ('synthetic-cvc', 'secret' if old_host else 'cvc')]
