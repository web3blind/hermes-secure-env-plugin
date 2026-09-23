"""Telegram command boundary. No secret values are accepted here."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

SAFE_USAGE = (
    "Use /senv <profile>, /senv <profile> <field1,field2>, /senv setup, "
    "/senv status or /senv cancel. Enter secrets only in the HTTPS form, never in chat. "
    "If you sent a secret here, delete the message and rotate the key with your provider."
)
DIRECT_USAGE = (
    "That profile is not configured. Use /senv <name> <field1,field2> to create its "
    "secure form. Enter values only in the HTTPS form, never in chat."
)
BOOTSTRAP_GUIDANCE = (
    "Secure environment ingress is not configured for this profile. Use /senv setup first. "
    "Do not send secrets in chat."
)
SAFE_ERROR = "The form is unavailable. Check /senv setup. Do not send secrets in chat."

_PROFILE_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_RESERVED = frozenset({"setup", "status", "cancel"})
_MAX_ARGUMENT_BYTES = 4096
_MAX_FIELDS = 32


@dataclass(frozen=True, slots=True)
class CommandRequest:
    profile: str
    fields: tuple[str, ...] = ()


def parse_selector(raw: str) -> str | None:
    if not isinstance(raw, str) or _PROFILE_RE.fullmatch(raw) is None:
        return None
    return raw


def parse_request(raw: str) -> CommandRequest | None:
    """Parse bounded profile/field metadata; assignments and values are never accepted."""
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > _MAX_ARGUMENT_BYTES:
        return None
    if any(char in raw for char in ("\r", "\n", "\x00")):
        return None
    parts = raw.split()
    if len(parts) not in {1, 2}:
        return None
    profile = parse_selector(parts[0])
    if profile is None:
        return None
    if len(parts) == 1:
        return CommandRequest(profile)
    if profile in _RESERVED:
        return None
    raw_fields = parts[1].split(",")
    if not 1 <= len(raw_fields) <= _MAX_FIELDS:
        return None
    fields: list[str] = []
    for field in raw_fields:
        if _FIELD_RE.fullmatch(field) is None or field in fields:
            return None
        fields.append(field)
    return CommandRequest(profile, tuple(fields))


class CommandController:
    def __init__(
        self,
        runtime,
        allowed_ids: frozenset[int],
        *,
        setup_handler=None,
        setup_authorized=None,
        allowed_ids_supplier=None,
        profile_definer=None,
        profile_exists=None,
        form_creator=None,
        status_reader=None,
    ):
        self.runtime = runtime
        self.allowed_ids = allowed_ids
        self.setup_handler = setup_handler
        self.setup_authorized = setup_authorized
        self.allowed_ids_supplier = allowed_ids_supplier
        self.profile_definer = profile_definer
        self.profile_exists = profile_exists
        self.form_creator = form_creator
        self.status_reader = status_reader

    async def handle(self, update, context):
        message = getattr(update, "effective_message", None)
        user = getattr(update, "effective_user", None)
        chat = getattr(update, "effective_chat", None)
        if (
            message is None
            or user is None
            or type(getattr(user, "id", None)) is not int
            or getattr(user, "id", 0) <= 0
            or getattr(user, "is_bot", True)
            or getattr(chat, "type", None) != "private"
            or getattr(message, "business_connection_id", None)
        ):
            return
        owner = user.id
        created = False
        operation = None
        try:
            text = getattr(message, "text", "") or ""
            command_parts = text.split(maxsplit=1)
            request = parse_request(command_parts[1]) if len(command_parts) == 2 else None
            allowed = self.allowed_ids_supplier() if self.allowed_ids_supplier else self.allowed_ids
            if owner not in allowed:
                bootstrap = bool(
                    self.setup_authorized is not None and self.setup_authorized(owner)
                )
                if request is not None and request.profile == "setup" and bootstrap:
                    pass
                elif request is not None and bootstrap:
                    await message.reply_text(BOOTSTRAP_GUIDANCE)
                    return
                else:
                    return
            if request is None:
                await message.reply_text(SAFE_USAGE)
                return
            selector = request.profile
            if selector == "cancel":
                await asyncio.to_thread(self.runtime.cancel, owner)
                await message.reply_text("The link has been cancelled.")
            elif selector == "setup":
                if self.setup_handler is None:
                    await message.reply_text(
                        "Installation assistance is unavailable in this session. No changes were made."
                    )
                else:
                    await self.setup_handler(update)
            elif selector == "status":
                reply = await asyncio.to_thread(self.status_reader, owner) if self.status_reader else await asyncio.to_thread(self.runtime.status)
                await message.reply_text(reply)
            else:
                if request.fields and self.profile_definer is None and self.form_creator is None:
                    await message.reply_text(SAFE_ERROR)
                    return

                reservation = (
                    self.runtime.reserve(owner)
                    if self.form_creator is not None
                    else None
                )

                def create_form():
                    if self.form_creator is not None:
                        return self.form_creator(
                            owner, selector, request.fields, reservation
                        )
                    definition = None
                    if request.fields:
                        definer = self.profile_definer
                        if definer is None:
                            raise RuntimeError("profile definition is unavailable")
                        definition = definer(owner, selector, request.fields)
                    elif self.profile_exists is not None and not self.profile_exists(selector):
                        return None, None
                    return definition, self.runtime.create(owner, selector)

                from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

                operation = asyncio.create_task(asyncio.to_thread(create_form))
                definition, links = await asyncio.shield(operation)
                if links is None:
                    await message.reply_text(DIRECT_USAGE)
                    return
                created = True
                buttons = [[InlineKeyboardButton("Open secure form", url=links["url"])]]
                if links.get("web_app_url"):
                    buttons.append(
                        [
                            InlineKeyboardButton(
                                "Open as Mini App",
                                web_app=WebAppInfo(url=links["web_app_url"]),
                            )
                        ]
                    )
                prefix = ""
                if definition is not None:
                    prefix = (
                        f"Fields: {', '.join(definition.keys)}. "
                        f"Destination: {definition.target}. "
                    )
                await message.reply_text(
                    prefix
                    + "This is a one-time form. Enter your secret only on the HTTPS page that opens. "
                    "Do not forward the link. It becomes invalid after submission.",
                    reply_markup=InlineKeyboardMarkup(buttons),
                )
        except asyncio.CancelledError:
            if operation is not None:
                try:
                    await asyncio.shield(operation)
                except BaseException:
                    pass
            await asyncio.to_thread(self.runtime.cancel, owner)
            raise
        except Exception as exc:
            from .setup_config import UnauthorizedOwnerError

            if isinstance(exc, UnauthorizedOwnerError):
                return
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
    return (
        "Open a private chat with the bot and use /senv <profile> or "
        "/senv <profile> <field1,field2>. Never include secret values in the command."
    )


def defensive_hook(*, event, **kwargs):
    parts = (getattr(event, "text", "") or "").split(maxsplit=1)
    if parts and parts[0].split("@", 1)[0].lower() == "/senv":
        if len(parts) > 1 and parse_request(parts[1]) is None:
            return {"action": "skip", "reason": "invalid secure ingress command"}
    return None
