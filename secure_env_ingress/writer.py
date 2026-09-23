"""Descriptor-safe, add-only dotenv writes with no value read/export API.

The public API deliberately returns key names and metadata only.  Callers must
bind a target before accepting secret input, then pass that binding to
``add_missing``.  This module is POSIX-oriented because its guarantees depend on
``O_NOFOLLOW``, ownership, Unix modes, advisory locks, and directory fsync.
"""
from __future__ import annotations

import errno
import io
import fcntl
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from dotenv.parser import parse_stream

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXISTING_RE = re.compile(rb"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=")
_MAX_ENV_BYTES = 16 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class WriterError(RuntimeError):
    """Base class for safe, value-free writer failures."""


class InsecureTargetError(WriterError):
    """The path, file type, ownership, or permissions failed closed."""


class TargetChangedError(WriterError):
    """The target no longer has the identity bound before secret entry."""


class DuplicateKeyError(WriterError):
    """An existing dotenv file contains an ambiguous duplicate key."""


@dataclass(frozen=True, slots=True)
class TargetBinding:
    """Identity captured before input; contains no secret data."""

    path: Path
    expected_uid: int
    parent_identity: tuple[int, int]
    file_identity: tuple[int, int, int, int, int] | None
    _pinned_fd: int = field(default=-1, repr=False, compare=False)

    def __del__(self):
        if self._pinned_fd >= 0:
            try:
                os.close(self._pinned_fd)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class WriteResult:
    """Value-free outcome of an add-only update."""

    added: tuple[str, ...]
    skipped: tuple[str, ...]


def _validate_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise InsecureTargetError("target must be an absolute file path")
    if any(part == ".." for part in path.parts):
        raise InsecureTargetError("target path traversal is forbidden")
    return path


def _open_parent(path: Path, *, create: bool, expected_uid: int) -> int:
    """Walk every parent using directory descriptors, never following symlinks."""
    path = _validate_path(path)
    fd = os.open("/", os.O_RDONLY | _DIRECTORY | _CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not create:
                    raise InsecureTargetError("target parent does not exist") from None
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                        dir_fd=fd,
                    )
                except OSError:
                    raise InsecureTargetError("target parent changed during creation") from None
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise InsecureTargetError("symlink or non-directory in target parents") from None
                raise
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise InsecureTargetError("target parent is not a directory")
        if info.st_uid != expected_uid:
            raise InsecureTargetError("target parent owner does not match runtime owner")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise InsecureTargetError("target parent is group/world writable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _validate_file(fd: int, expected_uid: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InsecureTargetError("target is not a regular file")
    if info.st_uid != expected_uid:
        raise InsecureTargetError("target owner does not match runtime owner")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise InsecureTargetError("target permissions must be exactly 0600")
    return info


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Bind identity plus mutation metadata to detect inode reuse/content changes."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_ctime_ns,
        info.st_mtime_ns,
        info.st_size,
    )


def _open_existing(parent_fd: int, name: str, expected_uid: int) -> tuple[int, os.stat_result] | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW | _CLOEXEC, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise InsecureTargetError("target symlinks are forbidden") from None
        raise
    try:
        return fd, _validate_file(fd, expected_uid)
    except BaseException:
        os.close(fd)
        raise


def bind_target(
    path: Path,
    *,
    expected_uid: int,
    create_parents: bool = False,
) -> TargetBinding:
    """Validate and bind a target before secret values are requested.

    With ``create_parents=True`` missing parents are created descriptor-relative
    with mode 0700.  The target file itself is never created by this function.
    """
    if isinstance(expected_uid, bool) or expected_uid < 0:
        raise ValueError("expected_uid must be a non-negative integer")
    path = _validate_path(path)
    parent_fd = _open_parent(path, create=create_parents, expected_uid=expected_uid)
    try:
        parent_info = os.fstat(parent_fd)
        opened = _open_existing(parent_fd, path.name, expected_uid)
        file_fd = -1
        if opened is None:
            file_identity = None
        else:
            file_fd, file_info = opened
            file_identity = _file_identity(file_info)
        return TargetBinding(
            path=path,
            expected_uid=expected_uid,
            parent_identity=(parent_info.st_dev, parent_info.st_ino),
            file_identity=file_identity,
            _pinned_fd=file_fd,
        )
    finally:
        os.close(parent_fd)


def quote_dotenv(value: str) -> str:
    """Encode a value as one double-quoted dotenv line fragment."""
    if not isinstance(value, str):
        raise TypeError("dotenv values must be strings")
    if "\x00" in value:
        raise ValueError("dotenv values cannot contain NUL")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    return f'"{escaped}"'


def _validate_values(values: Mapping[str, str]) -> tuple[str, ...]:
    if not isinstance(values, Mapping) or not values:
        raise ValueError("at least one key is required")
    keys: list[str] = []
    for key, value in values.items():
        if not isinstance(key, str) or _KEY_RE.fullmatch(key) is None:
            raise ValueError("invalid environment key")
        # Validate without retaining an additional encoded copy.
        quote_dotenv(value)
        keys.append(key)
    return tuple(keys)


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_ENV_BYTES:
            raise WriterError("target exceeds the safe size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _existing_keys(data: bytes) -> set[str]:
    names: set[str] = set()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise WriterError("invalid target encoding") from None
    for item in parse_stream(io.StringIO(text)):
        if item.error:
            raise WriterError("target contains malformed dotenv input")
        name = item.key
        if name is None:
            continue
        if name in names:
            raise DuplicateKeyError("target contains a duplicate environment key")
        names.add(name)
    return names


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise WriterError("failed to write target")
        view = view[written:]


def _lock(parent_fd: int, target_name: str, expected_uid: int) -> int:
    lock_name = f".{target_name}.secure-env.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | _NOFOLLOW | _CLOEXEC
    try:
        fd = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InsecureTargetError("lock symlinks are forbidden") from None
        raise
    try:
        _validate_file(fd, expected_uid)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _verify_binding(binding: TargetBinding, parent_fd: int, file_info: os.stat_result | None) -> None:
    parent_info = os.fstat(parent_fd)
    if (parent_info.st_dev, parent_info.st_ino) != binding.parent_identity:
        raise TargetChangedError("target parent changed after capability creation")
    current = _file_identity(file_info) if file_info is not None else None
    if current != binding.file_identity:
        raise TargetChangedError("target file changed after capability creation")


def add_missing(
    path: Path,
    values: Mapping[str, str],
    *,
    binding: TargetBinding,
    require_all_missing: bool = False,
) -> WriteResult:
    """Atomically add missing keys, never replacing existing assignments.

    No submitted value is returned, logged, or reread for confirmation.  The
    caller receives only added/skipped key names.
    """
    keys = _validate_values(values)
    path = _validate_path(path)
    if path != binding.path:
        raise TargetChangedError("target path does not match its capability")
    parent_fd = _open_parent(path, create=False, expected_uid=binding.expected_uid)
    lock_fd = -1
    temp_name: str | None = None
    parent_info = os.fstat(parent_fd)
    if (parent_info.st_dev, parent_info.st_ino) != binding.parent_identity:
        os.close(parent_fd)
        raise TargetChangedError("target parent changed after capability creation")
    try:
        lock_fd = _lock(parent_fd, path.name, binding.expected_uid)
        opened = _open_existing(parent_fd, path.name, binding.expected_uid)
        if opened is None:
            current_fd = -1
            current_info = None
            current = b""
        else:
            current_fd, current_info = opened
            try:
                current = _read_all(current_fd)
            finally:
                os.close(current_fd)
        _verify_binding(binding, parent_fd, current_info)
        existing = _existing_keys(current)
        added = tuple(key for key in keys if key not in existing)
        skipped = tuple(key for key in keys if key in existing)
        if require_all_missing and skipped:
            raise WriterError("one or more configured keys already exist")
        if not added:
            return WriteResult(added=(), skipped=skipped)

        suffix = b"" if not current or current.endswith(b"\n") else b"\n"
        additions = "".join(f"{key}={quote_dotenv(values[key])}\n" for key in added).encode("utf-8")
        replacement = current + suffix + additions

        for _ in range(128):
            candidate = f".{path.name}.tmp-{secrets.token_hex(16)}"
            try:
                temp_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                temp_name = candidate
                break
            except FileExistsError:
                continue
        else:
            raise WriterError("unable to allocate a temporary target")
        try:
            _validate_file(temp_fd, binding.expected_uid)
            _write_all(temp_fd, replacement)
            os.fsync(temp_fd)
        except BaseException:
            os.close(temp_fd)
            raise
        os.close(temp_fd)

        # Recheck the pathname immediately before replacement, while retaining
        # the stable parent descriptor and cooperative lock.
        latest = _open_existing(parent_fd, path.name, binding.expected_uid)
        if latest is None:
            if current_info is not None:
                raise TargetChangedError("target disappeared during update")
        else:
            latest_fd, latest_info = latest
            os.close(latest_fd)
            if current_info is None or _file_identity(latest_info) != _file_identity(current_info):
                raise TargetChangedError("target changed during update")
        os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
        os.fsync(parent_fd)
        return WriteResult(added=added, skipped=skipped)
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)
