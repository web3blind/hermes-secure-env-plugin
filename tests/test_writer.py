from __future__ import annotations

import hashlib
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from secure_env_ingress.writer import (
    DuplicateKeyError,
    InsecureTargetError,
    TargetChangedError,
    add_missing,
    bind_target,
    quote_dotenv,
)


def _digest(path: Path) -> bytes:
    return hashlib.sha256(path.read_bytes()).digest()


def test_adds_keys_durably_without_replacing_existing(tmp_path: Path) -> None:
    target = tmp_path / "private" / ".env"
    binding = bind_target(target, expected_uid=os.getuid(), create_parents=True)
    first = add_missing(target, {"OLD_KEY": "sample-one"}, binding=binding)
    rebound = bind_target(target, expected_uid=os.getuid())
    before = _digest(target)
    second = add_missing(
        target,
        {"OLD_KEY": "different-sample", "NEW_KEY": "quote' slash\\ unicode-λ\nline"},
        binding=rebound,
    )

    assert first.added == ("OLD_KEY",)
    assert second.added == ("NEW_KEY",)
    assert second.skipped == ("OLD_KEY",)
    assert _digest(target) != before
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    data = target.read_text(encoding="utf-8")
    assert data.count("OLD_KEY=") == 1
    assert data.count("NEW_KEY=") == 1
    assert "\\n" in data
    assert "λ" in data


def test_quote_dotenv_escapes_control_characters() -> None:
    encoded = quote_dotenv('a"b\\c\r\nd')
    assert encoded.startswith('"') and encoded.endswith('"')
    assert "\n" not in encoded
    assert "\r" not in encoded
    assert '\\"' in encoded
    assert "\\\\" in encoded


@pytest.mark.parametrize("key", ["", "bad.name", "1BAD", "A-B", "A=B"])
def test_rejects_invalid_keys_before_creating_file(tmp_path: Path, key: str) -> None:
    target = tmp_path / ".env"
    binding = bind_target(target, expected_uid=os.getuid())
    with pytest.raises(ValueError):
        add_missing(target, {key: "sample"}, binding=binding)
    assert not target.exists()


def test_rejects_symlink_target_and_symlink_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    os.chmod(real, 0o700)
    (real / ".env").write_text("", encoding="utf-8")
    os.chmod(real / ".env", 0o600)
    target_link = tmp_path / "target-link"
    target_link.symlink_to(real / ".env")
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real, target_is_directory=True)

    with pytest.raises(InsecureTargetError):
        bind_target(target_link, expected_uid=os.getuid())
    with pytest.raises(InsecureTargetError):
        bind_target(parent_link / ".env", expected_uid=os.getuid())


def test_rejects_wrong_permissions_owner_and_changed_parent(tmp_path: Path) -> None:
    target = tmp_path / "a" / ".env"
    binding = bind_target(target, expected_uid=os.getuid(), create_parents=True)
    target.touch(mode=0o600)
    os.chmod(target, 0o644)
    with pytest.raises(InsecureTargetError):
        bind_target(target, expected_uid=os.getuid())
    os.chmod(target, 0o600)
    with pytest.raises(InsecureTargetError):
        bind_target(target, expected_uid=os.getuid() + 1)

    moved = tmp_path / "moved"
    target.parent.rename(moved)
    target.parent.mkdir(mode=0o700)
    with pytest.raises(TargetChangedError):
        add_missing(target, {"NEW_KEY": "sample"}, binding=binding)


def test_changed_file_identity_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.touch(mode=0o600)
    binding = bind_target(target, expected_uid=os.getuid())
    target.unlink()
    target.touch(mode=0o600)
    with pytest.raises(TargetChangedError):
        add_missing(target, {"NEW_KEY": "sample"}, binding=binding)


def test_concurrent_add_is_serialized_and_add_only(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    binding = bind_target(target, expected_uid=os.getuid())

    def write(key: str) -> bool:
        try:
            add_missing(target, {key: "sample"}, binding=binding)
            return True
        except (TargetChangedError, BlockingIOError):
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(write, ["FIRST_KEY", "SECOND_KEY"]))
    assert outcomes.count(True) == 1
    assert target.read_text().count("_KEY=") == 1


def test_duplicate_existing_key_in_file_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("DUP=x\nDUP=y\n", encoding="utf-8")
    os.chmod(target, 0o600)
    binding = bind_target(target, expected_uid=os.getuid())
    before = _digest(target)
    with pytest.raises(DuplicateKeyError):
        add_missing(target, {"NEW_KEY": "sample"}, binding=binding)
    assert _digest(target) == before
