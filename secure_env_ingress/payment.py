"""Payment input contract. Validation is local, not card authorization or PCI compliance."""
from __future__ import annotations

import datetime as dt
import re
import unicodedata

PAYMENT_KEYS = ('Card number', 'Cardholder name (optional)', 'Expiry month',
                'Expiry year', 'CVC', 'Billing postal code (optional)')
PAYMENT_FIELDS = ('card_number', 'cardholder_name', 'exp_month', 'exp_year', 'cvc', 'billing_postal_code')


def payment_secret(values, *, today=None):
    """Fail closed without ever reflecting submitted values in errors."""
    if (not isinstance(values, list) or len(values) != 6 or
            any(not isinstance(v, str) or len(v) > limit or
                any(unicodedata.category(c).startswith('C') for c in v)
                for v, limit in zip(values, (19, 120, 2, 4, 4, 32)))):
        raise ValueError('invalid payment values')
    number, name, month, year, cvc, postal = values
    if (not re.fullmatch(r'[0-9]{12,19}', number) or
            not re.fullmatch(r'(?:0?[1-9]|1[0-2])', month) or
            not re.fullmatch(r'[0-9]{4}', year) or not re.fullmatch(r'[0-9]{3,4}', cvc)):
        raise ValueError('invalid payment values')
    digits = [int(c) for c in number[::-1]]
    checksum = sum(d if i % 2 == 0 else (2 * d - 9 if d >= 5 else 2 * d)
                   for i, d in enumerate(digits))
    today = today or dt.datetime.now(dt.timezone.utc).date()
    if (checksum % 10 or len(set(number)) == 1 or
            (int(year), int(month)) < (today.year, today.month) or int(year) > today.year + 20):
        raise ValueError('invalid payment values')
    # Verify native canonical fields rather than silently accepting an incompatible host.
    from agent.vault_store import PAYMENT_FIELDS as native_fields, REQUIRED_FIELDS
    if set(native_fields) != set(PAYMENT_FIELDS) or set(REQUIRED_FIELDS['payment']) != {
            'card_number', 'exp_month', 'exp_year', 'cvc'}:
        raise RuntimeError('unsupported native payment contract')
    return {key: value for key, value in zip(PAYMENT_FIELDS,
            (number, name.strip(), month.zfill(2), year, cvc, postal.strip())) if value}
