#!/usr/bin/env python3
"""Install validated certificate material into an atomic runtime generation."""

from __future__ import annotations

import os
import argparse
import grp
import json
import pwd
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from secure_env_ingress.tls import TLSValidationError, validate_certificate


class DeployError(RuntimeError):
    pass


CONFIRMATION = "DEPLOY-CERTIFICATE"


@dataclass(frozen=True)
class DeployResult:
    generation: Path
    certificate: Path
    private_key: Path


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_destination(path: Path) -> None:
    """Reject an existing symlink at or below the requested destination."""
    if not path.is_absolute():
        raise DeployError("destination root must be absolute")
    existing = path
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if existing.is_symlink():
        raise DeployError(f"destination traverses symlink: {existing}")
    resolved_existing = existing.resolve(strict=True)
    suffix = path.relative_to(existing)
    if resolved_existing.joinpath(suffix) != path:
        raise DeployError("destination path resolves through a symlink")
    if path.exists():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise DeployError("destination must be a real directory")


def _fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _trusted_when_root(path: Path) -> None:
    """Root must never bless source material controlled by another account."""
    if os.geteuid() != 0:
        return
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise DeployError(f"trusted source must be root-owned and not group/world writable: {path}")


def _trusted_chain_when_root(path: Path, boundary: Path) -> None:
    if os.geteuid() != 0:
        return
    current = path
    while True:
        _trusted_when_root(current)
        if current == boundary:
            return
        if current == current.parent or not _within(current, boundary):
            raise DeployError(f"trusted path escapes ownership boundary: {path}")
        current = current.parent


def _prepare_sources(
    source_certificate: str | os.PathLike[str],
    source_private_key: str | os.PathLike[str],
    trusted_source_root: str | os.PathLike[str],
    *,
    expected_ip: str,
    trust_roots: str | os.PathLike[str] | None,
) -> tuple[bytes, bytes]:
    try:
        source_root = Path(trusted_source_root).resolve(strict=True)
        cert = Path(source_certificate).resolve(strict=True)
        key = Path(source_private_key).resolve(strict=True)
    except OSError as exc:
        raise DeployError(f"cannot resolve trusted certificate sources: {exc}") from exc
    if not source_root.is_dir() or not _within(cert, source_root) or not _within(key, source_root):
        raise DeployError("certificate sources must resolve beneath a trusted directory")
    if not cert.is_file() or not key.is_file():
        raise DeployError("certificate sources must resolve to regular files")
    _trusted_chain_when_root(cert, Path(cert.anchor))
    _trusted_chain_when_root(key, Path(key.anchor))
    if trust_roots is not None:
        trusted_roots_path = Path(trust_roots).resolve(strict=True)
        _trusted_chain_when_root(trusted_roots_path, Path(trusted_roots_path.anchor))
    try:
        owner = cert.stat().st_uid
        validate_certificate(cert, key, expected_ip=expected_ip, trust_roots=trust_roots, owner_uid=owner)
        if owner != key.stat().st_uid:
            raise DeployError("certificate and key source owners differ")
        return cert.read_bytes(), key.read_bytes()
    except TLSValidationError as exc:
        raise DeployError(str(exc)) from exc


def _write_durable(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _deploy_unprivileged(cert_data: bytes, key_data: bytes, destination: Path) -> DeployResult:
    _safe_destination(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.stat().st_uid != os.geteuid():
        raise DeployError("destination must be owned by the deployment account")
    os.chmod(destination, 0o700)
    generations = destination / "generations"
    if generations.exists() and (generations.is_symlink() or not generations.is_dir()):
        raise DeployError("generations must be a real directory")
    generations.mkdir(mode=0o700, exist_ok=True)
    if generations.stat().st_uid != os.geteuid():
        raise DeployError("generations must be owned by the deployment account")
    os.chmod(generations, 0o700)

    token = uuid.uuid4().hex
    staging = generations / f".{token}.staging"
    generation = generations / token
    staging.mkdir(mode=0o700)
    try:
        _write_durable(staging / "fullchain.pem", cert_data, 0o644)
        _write_durable(staging / "privkey.pem", key_data, 0o600)
        _fsync_path(staging)
        staging.rename(generation)
        _fsync_path(generations)
        next_pointer = destination / f".current-{token}"
        next_pointer.symlink_to(Path("generations") / token, target_is_directory=True)
        os.replace(next_pointer, destination / "current")
        _fsync_path(destination)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return DeployResult(generation, generation / "fullchain.pem", generation / "privkey.pem")


def _drop_privileges(uid: int, gid: int) -> None:
    os.setgroups([])
    if hasattr(os, "setresgid"):
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
    else:  # pragma: no cover - Linux uses setresuid/setresgid
        os.setgid(gid)
        os.setuid(uid)
    if os.geteuid() != uid or os.getegid() != gid:
        raise DeployError("could not permanently drop deployment privileges")


def deploy_certificate(
    source_certificate: str | os.PathLike[str],
    source_private_key: str | os.PathLike[str],
    destination_root: str | os.PathLike[str],
    *,
    expected_ip: str,
    trusted_source_root: str | os.PathLike[str],
    trust_roots: str | os.PathLike[str] | None = None,
    owner_uid: int,
    owner_gid: int,
) -> DeployResult:
    """Validate then copy a cert/key pair and atomically switch ``current``.

    This function performs filesystem writes only.  It never invokes sudo,
    changes firewall state, obtains certificates, or restarts services.
    """
    if owner_uid <= 0 or owner_gid <= 0:
        raise DeployError("deployment requires a non-root destination account and group")
    destination = Path(destination_root)
    if not destination.is_absolute():
        raise DeployError("destination root must be absolute")
    cert_data, key_data = _prepare_sources(
        source_certificate,
        source_private_key,
        trusted_source_root,
        expected_ip=expected_ip,
        trust_roots=trust_roots,
    )
    effective_uid = os.geteuid()
    if effective_uid not in (0, owner_uid):
        raise DeployError("deployment must run as root or the destination owner")
    if effective_uid != 0 or owner_uid == 0:
        return _deploy_unprivileged(cert_data, key_data, destination)

    # Root reads only the trusted source. A child permanently drops to the
    # destination account before it creates or changes anything in that tree.
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no branch - exercised only by privileged operation
        os.close(read_fd)
        message: dict[str, object]
        try:
            _drop_privileges(owner_uid, owner_gid)
            os.umask(0o077)
            result = _deploy_unprivileged(cert_data, key_data, destination)
            message = {"ok": True, "generation": result.generation.name}
        except BaseException as exc:  # child must report, never unwind into caller
            message = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        try:
            os.write(write_fd, json.dumps(message).encode("utf-8"))
        finally:
            os.close(write_fd)
        os._exit(0 if message.get("ok") else 1)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        payload = stream.read(8192)
    _, status = os.waitpid(pid, 0)
    try:
        message = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DeployError("unprivileged deploy child returned no valid result") from exc
    if status != 0 or not message.get("ok"):
        raise DeployError(str(message.get("error", "unprivileged deploy child failed")))
    generation = destination / "generations" / str(message["generation"])
    return DeployResult(generation, generation / "fullchain.pem", generation / "privkey.pem")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate or atomically deploy certificate material")
    parser.add_argument("--apply", action="store_true", help="write only after exact confirmation")
    parser.add_argument("--confirm", help=f"required with --apply: {CONFIRMATION}")
    parser.add_argument("--source-certificate", required=True)
    parser.add_argument("--source-private-key", required=True)
    parser.add_argument("--trusted-source-root", required=True)
    parser.add_argument("--destination-root", required=True)
    parser.add_argument("--expected-ip", required=True)
    parser.add_argument("--trust-roots")
    parser.add_argument("--owner-user", required=True)
    parser.add_argument("--owner-group")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        account = pwd.getpwnam(args.owner_user)
        group = grp.getgrnam(args.owner_group) if args.owner_group else grp.getgrgid(account.pw_gid)
        destination = Path(args.destination_root)
        if not destination.is_absolute():
            raise DeployError("destination root must be absolute")
        _safe_destination(destination)
        _prepare_sources(
            args.source_certificate,
            args.source_private_key,
            args.trusted_source_root,
            expected_ip=args.expected_ip,
            trust_roots=args.trust_roots,
        )
        if not args.apply:
            print(json.dumps({
                "mode": "preflight",
                "valid": True,
                "writes_performed": False,
                "destination_root": str(destination),
                "owner_uid": account.pw_uid,
                "owner_gid": group.gr_gid,
            }, sort_keys=True))
            return 0
        if args.confirm != CONFIRMATION:
            raise DeployError(f"apply requires exact confirmation token {CONFIRMATION!r}")
        result = deploy_certificate(
            args.source_certificate,
            args.source_private_key,
            destination,
            expected_ip=args.expected_ip,
            trusted_source_root=args.trusted_source_root,
            trust_roots=args.trust_roots,
            owner_uid=account.pw_uid,
            owner_gid=group.gr_gid,
        )
        print(json.dumps({"mode": "apply", "generation": str(result.generation)}, sort_keys=True))
        return 0
    except (DeployError, KeyError, OSError, ValueError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
