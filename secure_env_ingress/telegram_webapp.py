"""Validation for Telegram Mini App ``initData``.

This implements Telegram's documented bot-token HMAC flow without a remote SDK.
The caller must still provide the expected Telegram user id from the capability;
valid signed data is authentication, not authorization by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import time
from urllib.parse import unquote_to_bytes

_MAX_INIT_DATA_BYTES = 8192
_MAX_FIELDS = 64
_HEX_ESCAPE = re.compile(r"%(?:[0-9A-Fa-f]{2})")
_HEX_HASH = re.compile(r"[0-9A-Fa-f]{64}\Z")


class InitDataError(ValueError):
    """Raised when Telegram launch data is malformed, invalid, or stale."""


@dataclass(frozen=True)
class VerifiedInitData:
    user_id: int
    auth_date: int
    user: dict[str, object]


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InitDataError("duplicate user field")
        result[key] = value
    return result


def _decode_component(value: str) -> str:
    # urllib deliberately tolerates bad '%' sequences; signed input must not.
    without_escapes = _HEX_ESCAPE.sub("", value)
    if "%" in without_escapes:
        raise InitDataError("malformed percent escape")
    try:
        return unquote_to_bytes(value.replace("+", " ")).decode("utf-8", "strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise InitDataError("invalid UTF-8") from exc


def _parse(raw: str) -> dict[str, str]:
    if not isinstance(raw, str) or not raw:
        raise InitDataError("invalid initData size")
    try:
        raw_size = len(raw.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise InitDataError("invalid UTF-8") from exc
    if raw_size > _MAX_INIT_DATA_BYTES:
        raise InitDataError("invalid initData size")
    parts = raw.split("&")
    if len(parts) > _MAX_FIELDS:
        raise InitDataError("too many fields")
    parsed: dict[str, str] = {}
    for part in parts:
        if not part or "=" not in part:
            raise InitDataError("malformed field")
        encoded_key, encoded_value = part.split("=", 1)
        key = _decode_component(encoded_key)
        value = _decode_component(encoded_value)
        if not key or key in parsed:
            raise InitDataError("duplicate or empty field")
        parsed[key] = value
    return parsed


def verify_init_data(
    raw: str,
    bot_token: str,
    *,
    expected_user_id: int,
    now: int | None = None,
    max_age_seconds: int = 300,
    future_skew_seconds: int = 30,
) -> VerifiedInitData:
    """Verify Telegram HMAC, freshness, strict user shape, and user binding.

    ``expected_user_id`` must come from trusted server-side session state. Both
    stale and implausibly future launch data are rejected. Duplicate parameters
    are rejected before signature checking to avoid parser differentials.
    """
    if not isinstance(bot_token, str) or not bot_token:
        raise InitDataError("missing bot token")
    if isinstance(expected_user_id, bool) or not isinstance(expected_user_id, int):
        raise InitDataError("invalid expected user")
    if max_age_seconds < 0 or future_skew_seconds < 0:
        raise InitDataError("invalid freshness policy")

    fields = _parse(raw)
    supplied_hash = fields.get("hash", "")
    if not _HEX_HASH.fullmatch(supplied_hash):
        raise InitDataError("invalid hash")

    # Bot-token HMAC validation excludes only `hash`. Telegram's separate
    # Ed25519 validation excludes `signature` too; these algorithms differ.
    checked = {key: value for key, value in fields.items() if key != "hash"}
    data_check_string = "\n".join(f"{key}={checked[key]}" for key in sorted(checked))
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    expected_hash = hmac.new(
        secret_key, data_check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied_hash.lower(), expected_hash):
        raise InitDataError("invalid signature")

    try:
        auth_date = int(fields["auth_date"], 10)
    except (KeyError, ValueError) as exc:
        raise InitDataError("invalid auth date") from exc
    if str(auth_date) != fields["auth_date"] or auth_date < 0:
        raise InitDataError("invalid auth date")
    current = int(time.time()) if now is None else int(now)
    if auth_date > current + future_skew_seconds or current - auth_date > max_age_seconds:
        raise InitDataError("expired initData")

    try:
        user = json.loads(fields["user"], object_pairs_hook=_unique_json_object)
    except (KeyError, json.JSONDecodeError, InitDataError) as exc:
        raise InitDataError("invalid user") from exc
    if not isinstance(user, dict):
        raise InitDataError("invalid user")
    user_id = user.get("id")
    if isinstance(user_id, bool) or not isinstance(user_id, int):
        raise InitDataError("invalid user id")
    if user_id != expected_user_id:
        raise InitDataError("wrong user")
    return VerifiedInitData(user_id=user_id, auth_date=auth_date, user=user)
