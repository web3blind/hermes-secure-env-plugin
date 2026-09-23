"""Telegram command boundary. No secret values are accepted here."""
from __future__ import annotations

import asyncio
import re

SAFE_USAGE = (
    "Use /senv <profile>, /senv setup, /senv status or /senv cancel. "
    "Enter secrets only in the HTTPS form, never in chat. "
    "If you sent a secret here, delete the message and rotate the key with your provider."
)
SAFE_ERROR = "The form is unavailable. Check /senv setup. Do not send secrets in chat."


def parse_selector(raw: str) -> str | None:
    if not isinstance(raw, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", raw):
        return None
    return raw


class CommandController:
    def __init__(self, runtime, allowed_ids: frozenset[int], *, setup_handler=None,
                 setup_authorized=None, allowed_ids_supplier=None):
        self.runtime = runtime
        self.allowed_ids = allowed_ids
        self.setup_handler = setup_handler
        self.setup_authorized = setup_authorized
        self.allowed_ids_supplier = allowed_ids_supplier

    async def handle(self, update, context):
        message = getattr(update, "effective_message", None)
        user = getattr(update, "effective_user", None)
        chat = getattr(update, "effective_chat", None)
        if (message is None or user is None or type(getattr(user, "id", None)) is not int
                or getattr(user, "id", 0) <= 0 or getattr(user, "is_bot", True)
                or getattr(chat, "type", None) != "private"
                or getattr(message, "business_connection_id", None)):
            return
        owner = user.id
        created = False
        creation = None
        try:
            text = getattr(message, "text", "") or ""
            parts = text.split(maxsplit=1)
            selector = parse_selector(parts[1]) if len(parts) == 2 else None
            allowed = self.allowed_ids_supplier() if self.allowed_ids_supplier else self.allowed_ids
            if owner not in allowed:
                if not (selector == "setup" and self.setup_authorized is not None
                        and self.setup_authorized(owner)):
                    return
            if selector is None:
                await message.reply_text(SAFE_USAGE)
                return
            if selector == "cancel":
                await asyncio.to_thread(self.runtime.cancel, owner)
                await message.reply_text("The link has been cancelled.")
            elif selector == "setup":
                if self.setup_handler is None:
                    await message.reply_text("Installation assistance is unavailable in this session. No changes were made.")
                else:
                    await self.setup_handler(update)
            elif selector == "status":
                reply = await asyncio.to_thread(self.runtime.status)
                await message.reply_text(reply)
            else:
                from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
                creation = asyncio.create_task(asyncio.to_thread(self.runtime.create, owner, selector))
                links = await asyncio.shield(creation)
                created = True
                buttons = [[InlineKeyboardButton("Open secure form", url=links["url"])]]
                if links.get("web_app_url"):
                    buttons.append([InlineKeyboardButton("Open as Mini App", web_app=WebAppInfo(url=links["web_app_url"]))])
                await message.reply_text(
                    "This is a one-time form. Enter your secret only on the HTTPS page that opens. "
                    "Do not forward the link. It becomes invalid after submission.",
                    reply_markup=InlineKeyboardMarkup(buttons),
                )
        except asyncio.CancelledError:
            # Finish the shielded worker before cancelling its session: lock ordering
            # alone cannot prevent a queued worker starting after cancellation.
            if creation is not None:
                try:
                    await asyncio.shield(creation)
                except Exception:
                    pass
            await asyncio.to_thread(self.runtime.cancel, owner)
            raise
        except Exception:
            if created:
                try:
                    await asyncio.to_thread(self.runtime.cancel, owner)
                except Exception:
                    pass
            try:
                await message.reply_text(SAFE_ERROR)
            except Exception:
                pass


def diagnostic_command(_args: str) -> str:
    return "Open a private chat with the bot and use /senv <profile>. Never include secrets in the command."


def defensive_hook(*, event, **kwargs):
    parts = (getattr(event, "text", "") or "").split(maxsplit=1)
    if parts and parts[0].split("@", 1)[0].lower() == "/senv":
        if len(parts) > 1 and parse_selector(parts[1]) is None:
            return {"action": "skip", "reason": "invalid secure ingress command"}
    return None
