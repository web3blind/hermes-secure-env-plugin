from unittest.mock import AsyncMock
from types import SimpleNamespace
import pytest

from secure_env_ingress.command import CommandController, parse_selector, SAFE_USAGE


@pytest.mark.parametrize('args', ['', 'KEY=fixture', '--path /tmp/a', 'a b', '../a', 'x\ny'])
def test_invalid_selector(args):
    assert parse_selector(args) is None


def test_valid_selector():
    assert parse_selector('ambient') == 'ambient'
    assert parse_selector('status') == 'status'


def update(user=88, kind='private', text='/senv ambient', business=None):
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user, is_bot=False),
        effective_chat=SimpleNamespace(type=kind),
        effective_message=SimpleNamespace(text=text, business_connection_id=business,
                                         reply_text=AsyncMock()),
    )


class Runtime:
    def __init__(self):
        self.calls = []
    def create(self, owner, name):
        self.calls.append((owner, name))
        return {'url': 'https://example.invalid/e#browser', 'web_app_url': 'https://example.invalid/e#mini'}
    def cancel(self, owner):
        self.calls.append(('cancel', owner))
    def status(self):
        return 'Readiness checked.'
    def preflight(self):
        return 'Preflight check.'


@pytest.mark.asyncio
async def test_authorized_create_and_separate_buttons():
    runtime = Runtime()
    controller = CommandController(runtime, frozenset({88}))
    u = update()
    await controller.handle(u, None)
    assert runtime.calls == [(88, 'ambient')]
    payload = u.effective_message.reply_text.call_args.kwargs['reply_markup'].to_dict()
    buttons = payload['inline_keyboard']
    assert 'url' in buttons[0][0] and 'web_app' in buttons[1][0]
    assert buttons[0][0]['text'] == 'Open secure form'
    assert buttons[1][0]['text'] == 'Open as Mini App'
    assert u.effective_message.reply_text.call_args.args[0].startswith('This is a one-time form.')


@pytest.mark.parametrize('user,kind,business', [(99,'private',None), (88,'group',None), (88,'private','x')])
@pytest.mark.asyncio
async def test_unauthorized_silent(user, kind, business):
    runtime = Runtime()
    u = update(user, kind, business=business)
    await CommandController(runtime, frozenset({88})).handle(u, None)
    assert not runtime.calls
    u.effective_message.reply_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_command_not_forwarded_or_echoed():
    runtime = Runtime()
    u = update(text='/senv KEY=fixture')
    await CommandController(runtime, frozenset({88})).handle(u, None)
    assert not runtime.calls
    assert u.effective_message.reply_text.call_args.args == (SAFE_USAGE,)


@pytest.mark.asyncio
async def test_failed_delivery_cancels_session():
    runtime = Runtime()
    u = update()
    u.effective_message.reply_text.side_effect = RuntimeError('fixture transport error')
    await CommandController(runtime, frozenset({88})).handle(u, None)
    assert runtime.calls[-1] == ('cancel', 88)


@pytest.mark.asyncio
async def test_cancelled_creation_does_not_leave_late_session():
    import asyncio
    import threading
    entered, finish = threading.Event(), threading.Event()
    runtime = Runtime()
    original = runtime.create
    def delayed(owner, name):
        entered.set()
        if not finish.wait(timeout=3):
            raise RuntimeError('test worker timed out')
        return original(owner, name)
    runtime.create = delayed
    task = asyncio.create_task(CommandController(runtime, frozenset({88})).handle(update(), None))
    assert await asyncio.to_thread(entered.wait, 3)
    task.cancel()
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert runtime.calls == [(88, 'ambient'), ('cancel', 88)]
