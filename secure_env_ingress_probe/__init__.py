"""Throwaway Phase 0 probe for Hermes secure environment ingress.

This module intentionally performs no secret write.  It exists only to exercise
supported plugin registration and gateway boundaries.
"""

from __future__ import annotations

from typing import Any

SAFE_REPLY = "Secure environment ingress probe handled outside the agent."
PROBE_URL = "https://example.invalid/secure-env-phase0"


def _is_senv_command(text: str) -> bool:
    """Recognize Telegram-style /senv and /senv@bot command tokens."""
    parts = (text or "").split(maxsplit=1)
    if not parts:
        return False
    token = parts[0].lower()
    return token == "/senv" or token.startswith("/senv@")


def _contains_assignment(text: str) -> bool:
    if not _is_senv_command(text):
        return False
    parts = text.lstrip().split(maxsplit=1)
    return len(parts) == 2 and "=" in parts[1]


def handle_senv(_raw_args: str) -> str:
    """Return only a constant acknowledgement; never interpolate arguments."""
    return SAFE_REPLY


def pre_gateway_dispatch(*, event: Any, **_kwargs: Any) -> dict[str, str] | None:
    """Drop assignment-shaped /senv text before auth, transcript, or agent paths."""
    if _contains_assignment(getattr(event, "text", "") or ""):
        return {"action": "skip", "reason": "senv assignment blocked by phase0 probe"}
    return None


def build_telegram_markup(url: str = PROBE_URL):
    """Build a PTB keyboard proving both URL button encodings are supported."""
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Open as link", url=url)],
            [
                InlineKeyboardButton(
                    "Open as Mini App", web_app=WebAppInfo(url=url)
                )
            ],
        ]
    )


async def telegram_senv(
    update: Any, _context: Any, *, allowed_ids: frozenset[int] = frozenset()
) -> None:
    """Consume Telegram /senv before the adapter's catch-all command handler.

    Delivery errors are swallowed deliberately: once this callback owns the
    update, failure must not replay the original command into Hermes.
    """
    message = getattr(update, "effective_message", None)
    user = getattr(update, "effective_user", None)
    chat = getattr(update, "effective_chat", None)
    if (
        message is None
        or getattr(user, "id", None) not in allowed_ids
        or getattr(user, "is_bot", True)
        or getattr(chat, "type", None) != "private"
        or getattr(message, "business_connection_id", None)
    ):
        return
    try:
        await message.reply_text(
            SAFE_REPLY,
            reply_markup=build_telegram_markup(),
        )
    except Exception:
        return


def wire_telegram(
    application: Any, _adapter: Any, *, allowed_ids: frozenset[int] = frozenset()
) -> None:
    """Register a narrowly scoped native command handler on the public surface."""
    from telegram.ext import CommandHandler

    async def on_senv(update, context):
        await telegram_senv(update, context, allowed_ids=allowed_ids)

    application.add_handler(CommandHandler("senv", on_senv))


def register(ctx: Any) -> None:
    ctx.register_command(
        "senv",
        handle_senv,
        description="Phase 0 secure environment ingress compatibility probe",
        args_hint="[profile]",
    )
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)
    configured = ctx.get_config("allowed_telegram_user_ids", [])
    allowed_ids = frozenset(
        value for value in configured if type(value) is int and value > 0
    ) if isinstance(configured, list) else frozenset()

    def factory(application, adapter):
        wire_telegram(application, adapter, allowed_ids=allowed_ids)

    ctx.register_platform_handler("telegram", factory)
