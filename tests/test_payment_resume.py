"""Narrow plugin-only cardholder classification, synthetic descriptors."""
import pytest
from agent.vault_login_classifier import LoginControl


def holder(**changes):
    row = dict(index=0, name='creditCardHolder creditCardHolder', label='Card holder*', type='text', formIndex=0, autocomplete='off')
    row.update(changes)
    return LoginControl.from_dict(row)


def test_computop_cardholder_fallback():
    from secure_env_ingress.payment_fill import classify_payment_control
    control = holder()
    result = classify_payment_control(control)
    assert result.token == 'cc-name' and result.control is control
    assert result.control.index == 0 and result.control.form_index == 0


@pytest.mark.parametrize('changes', [dict(name='other'), dict(label='Other'), dict(type='checkbox'),
    dict(type='password'), dict(formIndex=None), dict(autocomplete='one-time-code')])
def test_cardholder_fallback_is_narrow(changes):
    from secure_env_ingress.payment_fill import classify_payment_control
    assert classify_payment_control(holder(**changes)) is None


def test_native_classification_precedence():
    from secure_env_ingress.payment_fill import classify_payment_control
    assert classify_payment_control(holder(autocomplete='cc-number')).token == 'cc-number'
