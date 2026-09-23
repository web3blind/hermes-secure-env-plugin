"""Setup is an installation-only model handoff, never a value forwarding path."""
from unittest.mock import AsyncMock

import pytest

from secure_env_ingress.command import CommandController
from test_command import Runtime, update


@pytest.mark.asyncio
async def test_setup_delegates_installation_without_constructing_runtime():
    runtime = Runtime()
    setup = AsyncMock()
    u = update(text='/senv setup')
    await CommandController(runtime, frozenset({88}), setup_handler=setup).handle(u, None)
    setup.assert_awaited_once_with(u)
    assert runtime.calls == []


@pytest.mark.asyncio
async def test_bootstrap_is_only_for_exact_setup_and_not_normal_ingress():
    setup = AsyncMock()
    runtime = Runtime()
    controller = CommandController(runtime, frozenset(), setup_handler=setup,
                                   setup_authorized=lambda user: user == 88)
    await controller.handle(update(text='/senv setup'), None)
    setup.assert_awaited_once()
    for text in ['/senv service', '/senv status', '/senv cancel', '/senv setup KEY=do-not-forward']:
        await controller.handle(update(text=text), None)
    assert setup.await_count == 1
    assert runtime.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize('text', ['/senv setup KEY=value', '/senv setup\nfixture-secret', '/senv SETUP', '/senv setup=secret'])
async def test_setup_arguments_never_reach_model(text):
    setup = AsyncMock()
    u = update(text=text)
    await CommandController(Runtime(), frozenset({88}), setup_handler=setup).handle(u, None)
    setup.assert_not_awaited()
    assert 'fixture-secret' not in repr(u.effective_message.reply_text.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize('user,kind,business,is_bot', [(99,'private',None,False), (88,'group',None,False), (88,'private','business',False), (88,'private',None,True)])
async def test_setup_never_relaxes_auth(user, kind, business, is_bot):
    setup = AsyncMock()
    u = update(user, kind, text='/senv setup', business=business)
    u.effective_user.is_bot = is_bot
    await CommandController(Runtime(), frozenset({88}), setup_handler=setup).handle(u, None)
    setup.assert_not_awaited()
    u.effective_message.reply_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_setup_failure_is_safe_not_fake_success():
    setup = AsyncMock(side_effect=RuntimeError('do-not-echo'))
    u = update(text='/senv setup')
    await CommandController(Runtime(), frozenset({88}), setup_handler=setup).handle(u, None)
    assert 'do-not-echo' not in repr(u.effective_message.reply_text.call_args_list)
    assert 'unavailable' in u.effective_message.reply_text.call_args.args[0].lower()
