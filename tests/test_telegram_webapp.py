from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import urlencode

import pytest

from secure_env_ingress.telegram_webapp import InitDataError, verify_init_data


def _signed(token: str, *, user_id: int = 42, auth_date: int = 1_700_000_000, **extra: str) -> str:
    fields = {
        "auth_date": str(auth_date),
        "query_id": "AAE-test",
        "user": json.dumps({"id": user_id, "first_name": "Test"}, separators=(",", ":")),
        **extra,
    }
    check = "\n".join(f"{key}={fields[key]}" for key in sorted(fields))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    fields["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(fields)


def test_verifies_official_hmac_and_bound_user() -> None:
    data = verify_init_data(
        _signed("123:bot-token"),
        "123:bot-token",
        expected_user_id=42,
        now=1_700_000_100,
        max_age_seconds=300,
    )
    assert data.user_id == 42
    assert data.auth_date == 1_700_000_000


def test_bot_token_hmac_includes_telegram_signature_field() -> None:
    data = verify_init_data(
        _signed("123:bot-token", signature="telegram-third-party-signature"),
        "123:bot-token",
        expected_user_id=42,
        now=1_700_000_100,
    )
    assert data.user_id == 42


@pytest.mark.parametrize("mutation", ["forged", "stale", "future", "wrong-user", "duplicate"])
def test_rejects_invalid_or_ambiguous_init_data(mutation: str) -> None:
    raw = _signed("123:bot-token")
    kwargs = {"expected_user_id": 42, "now": 1_700_000_100, "max_age_seconds": 300}
    if mutation == "forged":
        raw = raw.replace("AAE-test", "AAE-evil")
    elif mutation == "stale":
        kwargs["now"] = 1_700_001_000
    elif mutation == "future":
        kwargs["now"] = 1_699_999_000
    elif mutation == "wrong-user":
        kwargs["expected_user_id"] = 7
    else:
        raw += "&auth_date=1700000000"
    with pytest.raises(InitDataError):
        verify_init_data(raw, "123:bot-token", **kwargs)


def test_rejects_malformed_user_and_duplicate_hash() -> None:
    malformed = _signed("token", user="null")
    with pytest.raises(InitDataError):
        verify_init_data(malformed, "token", expected_user_id=42, now=1_700_000_100)

    duplicate_hash = _signed("token") + "&hash=" + "0" * 64
    with pytest.raises(InitDataError):
        verify_init_data(duplicate_hash, "token", expected_user_id=42, now=1_700_000_100)


def test_rejects_duplicate_user_fields_and_invalid_unicode() -> None:
    duplicate_user_id = _signed("token", user='{"id":42,"id":7}')
    with pytest.raises(InitDataError):
        verify_init_data(duplicate_user_id, "token", expected_user_id=7, now=1_700_000_100)

    with pytest.raises(InitDataError):
        verify_init_data("user=%ED%A0%80", "token", expected_user_id=42, now=1_700_000_100)

    with pytest.raises(InitDataError):
        verify_init_data("\ud800", "token", expected_user_id=42, now=1_700_000_100)
