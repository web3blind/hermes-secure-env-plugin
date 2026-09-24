"""Command provenance cannot be reused by inherited asyncio contexts."""
import asyncio
from pathlib import Path

import pytest
from secure_env_ingress.plugin import Captured


@pytest.mark.asyncio
async def test_capture_is_single_use_and_bound_to_original_task():
    home = Path('/fixture/profile')
    captured = Captured(home, 'service', ('discord', 'opaque-id'), 'session', asyncio.current_task())

    async def inherited_task():
        return captured.consume('service', home)

    assert await asyncio.create_task(inherited_task()) is False
    assert captured.consume('different', home) is False
    assert captured.consume('service', Path('/fixture/another')) is False
    assert captured.consume('service', home) is True
    assert captured.consume('service', home) is False
