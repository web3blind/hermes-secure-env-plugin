"""Installation-only handoff using Hermes consent and routing surfaces."""
from __future__ import annotations

import io
import os
from pathlib import Path
import re
import stat

from dotenv import dotenv_values

SETUP_REQUEST = (
    'Please install or diagnose secure-env-ingress for this Hermes profile. '
    'Load skill_view(name="secure-env-ingress:setup") and use its reviewed scripts first. '
    'Do the installation yourself with available tools; recover from script failures if safe. '
    'Use normal approvals for privileged changes. This is installation ONLY: never ask for '
    'secret values, read or print .env contents, private keys, bot credentials or form links. '
    'Do not restart the gateway without separate owner approval. '
    'Verify each completed step and distinguish installed, activated and externally tested.'
)
SETUP_BUTTON = 'Set up secure-env-ingress using skill secure-env-ingress:setup'


def numeric_owner_ids(raw):
    """No wildcard, negative IDs, username authorization or allow-all inference."""
    if not isinstance(raw, str):
        return frozenset()
    parts = [part.strip() for part in raw.split(',')]
    if not parts or any(re.fullmatch(r'[1-9][0-9]*', part) is None for part in parts):
        return frozenset()
    return frozenset(int(part) for part in parts)


def bootstrap_owner_ids(home: Path):
    """Read only this profile's explicit allowlist, never the process-global env."""
    fd = None
    try:
        home = Path(home)
        if not home.is_absolute():
            return frozenset()
        for parent in (home, *home.parents):
            info = parent.lstat()
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if not stat.S_ISDIR(info.st_mode) or (info.st_mode & 0o022 and not sticky_root):
                return frozenset()
        fd = os.open(home / '.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 1024 * 1024):
            return frozenset()
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            fd = None
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return frozenset()
        values = dotenv_values(stream=io.StringIO(raw), interpolate=False)
        return numeric_owner_ids(values.get('TELEGRAM_ALLOWED_USERS'))
    except (OSError, ValueError, UnicodeError):
        return frozenset()
    finally:
        if fd is not None:
            os.close(fd)


def setup_session_key(adapter, update):
    """Use native thread normalization, without constructing an event from raw text."""
    from gateway.session import build_session_key
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    thread = adapter._effective_message_thread_id(message)
    source = adapter.build_source(
        chat_id=str(chat.id), chat_type='dm', user_id=str(user.id),
        thread_id=thread, message_id=str(message.message_id), is_bot=False,
    )
    return build_session_key(source, profile=source.profile)


def setup_paused():
    try:
        from agent.estop import paused_reply
    except ImportError:
        # Older Hermes has no pause surface; injection still obeys host permissions.
        return False
    try:
        return paused_reply() is not None
    except Exception:
        return True


async def handoff_setup(ctx, adapter, update):
    """A denied injection is not bypassed: a button sends a new user-authored turn."""
    from telegram import KeyboardButton, ReplyKeyboardMarkup
    message = update.effective_message
    if setup_paused():
        await message.reply_text('Hermes is paused. Resume it before starting installation.')
        return
    accepted = False
    try:
        session_key = setup_session_key(adapter, update)
        accepted = ctx.inject_message(SETUP_REQUEST, role='user', session_key=session_key) is True
    except Exception:
        # Do not expose transport errors, update contents or profile configuration.
        pass
    keyboard = ReplyKeyboardMarkup([[KeyboardButton(SETUP_BUTTON)]],
                                   resize_keyboard=True, one_time_keyboard=True)
    if accepted:
        text = ('Installation assistance was queued for this conversation. If Hermes is busy, '
                'it will run as a follow-up. This is not an installation success report. '
                'If no setup response arrives, tap the setup button to request a normal agent turn. '
                'Never send secret values in chat.')
    else:
        text = ('Tap the setup button below to ask Hermes to install this plugin for you. '
                'This sends a normal installation request; no shell commands or configuration edits '
                'are required from you. Administrative changes still require your approval. '
                'Never send secret values in chat.')
    await message.reply_text(text, reply_markup=keyboard)
