from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from types import SimpleNamespace

import pytest

from secure_env_ingress.setup_handoff import (
    bootstrap_owner_ids, numeric_owner_ids, handoff_setup, SETUP_REQUEST, SETUP_BUTTON,
)


@pytest.mark.parametrize('raw', ['', '*', '88,*', '@owner', '-88', '0', 'True', '88 99', '${OWNER}', None])
def test_bootstrap_ids_fail_closed(raw):
    assert numeric_owner_ids(raw) == frozenset()


def test_numeric_ids():
    assert numeric_owner_ids('88, 99') == frozenset({88, 99})


@pytest.fixture
def private_root():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix='senv-auth-', dir='/tmp') as directory:
        yield Path(directory)


def test_profile_bootstrap_never_uses_process_environment(private_root, monkeypatch):
    tmp_path = private_root
    monkeypatch.setenv('TELEGRAM_ALLOWED_USERS', '99')
    monkeypatch.setenv('TELEGRAM_ALLOW_ALL_USERS', 'true')
    first, second = tmp_path / 'first', tmp_path / 'second'
    for home, owner in ((first, 88), (second, 77)):
        home.mkdir(mode=0o700)
        env = home / '.env'
        env.write_text(f'TELEGRAM_ALLOWED_USERS={owner}\nUNRELATED=fake-private-sentinel\n')
        env.chmod(0o600)
    assert bootstrap_owner_ids(first) == frozenset({88})
    assert bootstrap_owner_ids(second) == frozenset({77})
    assert bootstrap_owner_ids(tmp_path / 'missing') == frozenset()
    (first / '.env').chmod(0o644)
    assert bootstrap_owner_ids(first) == frozenset()
    (first / '.env').unlink()
    (first / '.env').symlink_to(second / '.env')
    assert bootstrap_owner_ids(first) == frozenset()


@pytest.mark.asyncio
@pytest.mark.parametrize('accepted', [True, False])
async def test_only_constant_installation_prompt_is_injected(monkeypatch, accepted):
    ctx = SimpleNamespace(inject_message=MagicMock(return_value=accepted))
    update = SimpleNamespace(effective_message=SimpleNamespace(
        text='/senv setup', reply_to_message=SimpleNamespace(text='fixture-private-reply'),
        photo='fixture-private-photo', reply_text=AsyncMock()))
    monkeypatch.setattr('secure_env_ingress.setup_handoff.setup_paused', lambda: False)
    monkeypatch.setattr('secure_env_ingress.setup_handoff.setup_session_key', lambda *_: 'test-session')
    await handoff_setup(ctx, object(), update)
    ctx.inject_message.assert_called_once_with(SETUP_REQUEST, role='user', session_key='test-session')
    response = update.effective_message.reply_text.call_args
    assert 'fixture-private' not in repr(response)
    assert response.kwargs['reply_markup'].keyboard[0][0].text == SETUP_BUTTON
    assert 'success report' in response.args[0] if accepted else 'Tap the setup button' in response.args[0]


@pytest.mark.asyncio
async def test_paused_handoff_never_starts_agent(monkeypatch):
    ctx = SimpleNamespace(inject_message=MagicMock())
    update = SimpleNamespace(effective_message=SimpleNamespace(reply_text=AsyncMock()))
    monkeypatch.setattr('secure_env_ingress.setup_handoff.setup_paused', lambda: True)
    await handoff_setup(ctx, object(), update)
    ctx.inject_message.assert_not_called()
    assert 'paused' in update.effective_message.reply_text.call_args.args[0]
