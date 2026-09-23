#!/usr/bin/env python3
"""Plan or explicitly apply the privileged TLS bootstrap.

The helper does not install Certbot or alter a firewall.  Those are explicit
operator prerequisites.  Apply mode installs a reviewed, root-owned copy of
the deploy helper and a generated fixed-argument Certbot deploy hook.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import grp
import re
import socket
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from secure_env_ingress.tls import TLSValidationError, validate_certificate

CONFIRMATION = "PRIVILEGED-TLS-SETUP"
DEPLOY_CONFIRMATION = "DEPLOY-CERTIFICATE"
CERTBOT = "/snap/bin/certbot"
INSTALL = "/usr/bin/install"
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_HELPER_DIR = Path("/usr/local/libexec/hermes-secure-env")
_DEFAULT_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/hermes-secure-env")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


@dataclass(frozen=True)
class SetupConfig:
    public_ip: str
    runtime_dir: Path
    hermes_user: str
    plugin_port: int = 18443
    email: str | None = None
    staging: bool = True
    hermes_group: str | None = None
    certificate_name: str | None = None
    certbot_executable: Path = Path(CERTBOT)
    python_executable: Path = Path("/usr/bin/python3")
    deploy_helper_source: Path = _PROJECT_ROOT / "scripts" / "deploy_certificate.py"
    package_init_source: Path = _PROJECT_ROOT / "secure_env_ingress" / "__init__.py"
    tls_helper_source: Path = _PROJECT_ROOT / "secure_env_ingress" / "tls.py"
    helper_install_dir: Path = _DEFAULT_HELPER_DIR
    hook_install_path: Path = _DEFAULT_HOOK
    trusted_source_root: Path = Path("/etc/letsencrypt")
    trust_roots: Path | None = None
    renewal_scheduler_verified: bool = False

    @property
    def effective_group(self) -> str:
        return self.hermes_group or self.hermes_user

    @property
    def effective_certificate_name(self) -> str:
        base = ("ip-" + self.public_ip.replace(":", "_")) if ":" in self.public_ip else self.public_ip
        return (self.certificate_name or base) + ("-staging" if self.staging else "")

    @property
    def lineage_dir(self) -> Path:
        return self.trusted_source_root / "live" / self.effective_certificate_name


@dataclass(frozen=True)
class RootInstall:
    destination: Path
    mode: int
    source: Path | None = None
    content: bytes | None = None


@dataclass(frozen=True)
class SetupReport:
    applied: bool
    commands: tuple[tuple[str, ...], ...]
    installs: tuple[RootInstall, ...] = ()


def _absolute(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if "\x00" in str(path) or "\n" in str(path) or "\r" in str(path):
        raise ValueError(f"{label} contains an unsafe character")


def _validate_config(config: SetupConfig) -> None:
    ipaddress.ip_address(config.public_ip)
    if not 1 <= config.plugin_port <= 65535:
        raise ValueError("plugin_port must be in 1..65535")
    if not config.hermes_user or config.hermes_user.startswith("-") or any(c.isspace() for c in config.hermes_user):
        raise ValueError("hermes_user is invalid")
    if not config.effective_group or config.effective_group.startswith("-") or any(c.isspace() for c in config.effective_group):
        raise ValueError("hermes_group is invalid")
    if not _SAFE_NAME.fullmatch(config.effective_certificate_name):
        raise ValueError("certificate_name must contain only letters, digits, dot, underscore, or hyphen")
    for label, path in (
        ("runtime_dir", config.runtime_dir),
        ("certbot_executable", config.certbot_executable),
        ("python_executable", config.python_executable),
        ("deploy_helper_source", config.deploy_helper_source),
        ("package_init_source", config.package_init_source),
        ("tls_helper_source", config.tls_helper_source),
        ("helper_install_dir", config.helper_install_dir),
        ("hook_install_path", config.hook_install_path),
        ("trusted_source_root", config.trusted_source_root),
    ):
        _absolute(path, label)
    if config.trust_roots is not None:
        _absolute(config.trust_roots, "trust_roots")


def _shell_quote(value: str | Path) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ValueError("deploy hook argument contains an unsafe character")
    return "'" + text.replace("'", "'\"'\"'") + "'"


def build_deploy_wrapper(config: SetupConfig) -> bytes:
    """Generate a hook with fixed paths; no Certbot environment is trusted."""
    _validate_config(config)
    helper = config.helper_install_dir / "deploy_certificate.py"
    argv: list[str | Path] = [
        config.python_executable,
        "-E",
        "-s",
        helper,
        "--apply",
        "--confirm",
        DEPLOY_CONFIRMATION,
        "--source-certificate",
        config.lineage_dir / "fullchain.pem",
        "--source-private-key",
        config.lineage_dir / "privkey.pem",
        "--trusted-source-root",
        config.trusted_source_root,
        "--destination-root",
        config.runtime_dir,
        "--expected-ip",
        config.public_ip,
        "--owner-user",
        config.hermes_user,
        "--owner-group",
        config.effective_group,
    ]
    # The installed hook always requires the public system trust store.
    # Custom test roots must never promote staging material into runtime.
    # The environment may select a no-op, never a source path or executable.
    lineage_guard = 'case "${RENEWED_LINEAGE:-}" in ""|' + _shell_quote(config.lineage_dir) + ') ;; *) exit 0 ;; esac\n'
    return ("#!/bin/sh\nset -eu\n" + lineage_guard + "exec " + " ".join(_shell_quote(item) for item in argv) + "\n").encode("utf-8")


def build_root_installs(config: SetupConfig) -> tuple[RootInstall, ...]:
    _validate_config(config)
    package = config.helper_install_dir / "secure_env_ingress"
    return (
        RootInstall(config.helper_install_dir / "deploy_certificate.py", 0o755, source=config.deploy_helper_source),
        RootInstall(package / "__init__.py", 0o644, source=config.package_init_source),
        RootInstall(package / "tls.py", 0o644, source=config.tls_helper_source),
        RootInstall(config.hook_install_path, 0o755, content=build_deploy_wrapper(config)),
    )


def _preparation_commands(config: SetupConfig) -> tuple[tuple[str, ...], ...]:
    package = config.helper_install_dir / "secure_env_ingress"
    return (
        (str(config.python_executable), "-E", "-s", "-c", "import cryptography,sys; sys.exit(0 if cryptography.__version__.split('.')[0] == '50' else 1)"),
        (INSTALL, "-d", "-m", "0755", "-o", "root", "-g", "root", str(config.helper_install_dir)),
        (INSTALL, "-d", "-m", "0755", "-o", "root", "-g", "root", str(package)),
        (INSTALL, "-d", "-m", "0755", "-o", "root", "-g", "root", str(config.hook_install_path.parent)),
    )


def build_setup_commands(config: SetupConfig) -> tuple[tuple[str, ...], ...]:
    _validate_config(config)
    certbot = [
        str(config.certbot_executable),
        "certonly",
        "--standalone",
        "--non-interactive",
        "--agree-tos",
        "--preferred-profile",
        "shortlived",
        "--cert-name",
        config.effective_certificate_name,
    ]
    if config.staging:
        certbot.extend(("--staging", "--no-directory-hooks"))
    if config.email:
        certbot.extend(("--email", config.email))
    else:
        certbot.append("--register-unsafely-without-email")
    certbot.extend(("--ip-address", config.public_ip))
    commands = [] if config.staging else list(_preparation_commands(config))
    commands.append(tuple(certbot))
    if not config.staging:
        commands.append((str(config.certbot_executable), "renew", "--dry-run", "--cert-name", config.effective_certificate_name, "--no-directory-hooks"))
    return tuple(commands)


def validate_trusted_execution_path(
    path: Path,
    *,
    trusted_uid: int = 0,
    boundary: Path = Path("/"),
) -> None:
    """Require a regular file and every component through boundary to be trusted."""
    _absolute(path, "execution path")
    _absolute(boundary, "trust boundary")
    try:
        relative = path.relative_to(boundary)
    except ValueError as exc:
        raise PermissionError(f"execution path escapes trust boundary: {path}") from exc
    current = boundary
    components = (boundary, *(boundary / Path(*relative.parts[:index]) for index in range(1, len(relative.parts) + 1)))
    for current in components:
        try:
            info = current.lstat()
        except OSError as exc:
            raise PermissionError(f"cannot inspect trusted execution path {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise PermissionError(f"trusted execution path contains symlink: {current}")
        if info.st_uid != trusted_uid:
            raise PermissionError(f"trusted execution path is not owned by uid {trusted_uid}: {current}")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(f"trusted execution path is group/world writable: {current}")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise PermissionError(f"trusted execution target is not a regular file: {path}")


def _root_environment() -> dict[str, str]:
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


def _read_trusted_source(path: Path, *, trusted_uid: int = 0, boundary: Path = Path("/")) -> bytes:
    """Read from the verified descriptor, never reopen a validated pathname.

    Non-default UID/boundary are solely for unprivileged regression tests.
    """
    relative = path.relative_to(boundary)
    if not relative.parts or ".." in relative.parts:
        raise PermissionError("source escapes trusted boundary")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = os.open(boundary, flags | os.O_DIRECTORY)
    try:
        for index, part in enumerate(relative.parts):
            info = os.fstat(directory)
            if info.st_uid != trusted_uid or info.st_mode & 0o022:
                raise PermissionError("untrusted source ancestor")
            last = index == len(relative.parts) - 1
            fd = os.open(part, flags | (0 if last else os.O_DIRECTORY), dir_fd=directory)
            if not last:
                os.close(directory)
                directory = fd
                continue
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != trusted_uid
                        or info.st_mode & 0o022 or info.st_nlink != 1
                        or info.st_size > 1024 * 1024):
                    raise PermissionError("unsafe trusted source file")
                data = source.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise PermissionError("trusted source too large")
                return data
    finally:
        os.close(directory)
    raise PermissionError("missing source file")


def _validate_source(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise FileNotFoundError(f"required setup source is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PermissionError(f"setup source must be a regular non-symlink file: {path}")


def _trusted_existing_ancestor(path: Path) -> Path:
    current = path
    while not current.exists() and not current.is_symlink():
        if current == current.parent:
            break
        current = current.parent
    return current


def _validate_default_prerequisites(config: SetupConfig, installs: tuple[RootInstall, ...]) -> None:
    if os.geteuid() != 0:
        raise PermissionError("apply must run as root; preflight remains unprivileged")
    if not config.renewal_scheduler_verified:
        raise PermissionError(
            "apply requires --renewal-scheduler-verified after the operator confirms an active "
            "Certbot-managed systemd timer or equivalent packaged scheduler"
        )
    validate_trusted_execution_path(Path(__file__).resolve(strict=True))
    account = pwd.getpwnam(config.hermes_user)
    group = grp.getgrnam(config.effective_group)
    if account.pw_uid == 0 or group.gr_gid == 0:
        raise ValueError("runtime account and group must be non-root")
    for executable in (Path(INSTALL), config.python_executable, config.certbot_executable):
        _validate_executable(executable)
    _validate_certbot_version(config.certbot_executable)
    for item in installs:
        if item.source is not None:
            validate_trusted_execution_path(item.source)
        ancestor = _trusted_existing_ancestor(item.destination.parent)
        validate_trusted_execution_path(ancestor) if ancestor.is_file() else _validate_trusted_directory(ancestor)


def _validate_executable(path: Path) -> None:
    # Root-owned symlinks (python3, snap aliases) are valid only when both
    # the alias ancestry and fully resolved executable are trusted.
    for component in (path, *path.parents):
        info = component.lstat()
        if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
            raise PermissionError("untrusted executable alias ancestry")
    validate_trusted_execution_path(path.resolve(strict=True))


def _validate_certbot_version(executable: Path) -> None:
    try:
        completed = subprocess.run(
            (str(executable), "--version"), capture_output=True, text=True, check=True, timeout=10, shell=False, cwd="/", env=_root_environment()
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"cannot run required Certbot executable {executable}: {exc}") from exc
    match = re.search(r"(?:certbot\s+)?(\d+)\.(\d+)(?:\.\d+)?", completed.stdout or completed.stderr)
    if match is None or (int(match.group(1)), int(match.group(2))) < (5, 4):
        observed = (completed.stdout or completed.stderr).strip() or "unknown version"
        raise RuntimeError(f"Certbot >= 5.4 is required for this IP-certificate flow; observed: {observed}")


def _validate_trusted_directory(path: Path) -> None:
    _absolute(path, "trusted directory")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PermissionError(f"trusted install path is not a real directory: {current}")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(f"trusted install directory is not root-owned and non-writable: {current}")


def _install_root_file(item: RootInstall) -> None:
    if os.geteuid() != 0:
        raise PermissionError("root-owned helper installation requires root")
    _validate_trusted_directory(item.destination.parent)
    if (item.source is None) == (item.content is None):
        raise ValueError("root install must have exactly one source or generated content")
    data = item.content
    if item.source is not None:
        data = _read_trusted_source(item.source)
    if data is None:
        raise ValueError("missing root install content")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{item.destination.name}.", dir=item.destination.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, item.mode)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, item.destination)
        directory_fd = os.open(item.destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def run_setup(
    config: SetupConfig,
    *,
    apply: bool = False,
    confirmation: str | None = None,
    execute: Callable[[Sequence[str]], object] | None = None,
    install: Callable[[RootInstall], object] | None = None,
) -> SetupReport:
    """Return a plan by default; apply only after exact confirmation.

    Injecting ``execute``/``install`` is the non-root test seam.  The real CLI
    always uses the prerequisite checks and root-only installer below.
    """
    commands = build_setup_commands(config)
    installs = () if config.staging else build_root_installs(config)
    if not apply:
        return SetupReport(applied=False, commands=commands, installs=installs)
    if confirmation != CONFIRMATION:
        raise PermissionError(f"apply requires exact confirmation token {CONFIRMATION!r}")
    injected = execute is not None or install is not None
    if injected and (execute is None or install is None):
        # Backward-compatible executor-only test seam: installs are deliberately
        # not written. Real CLI never supplies either callback.
        if execute is None:
            raise ValueError("injected install requires an injected executor")
        def no_op_install(item):
            return None
        install = no_op_install
    if not injected:
        _validate_default_prerequisites(config, installs)
    runner = execute or (lambda argv: subprocess.run(argv, check=True, shell=False, cwd="/", env=_root_environment()))
    installer = install or _install_root_file
    preparation_count = 0 if config.staging else len(_preparation_commands(config))
    for command in commands[:preparation_count]:
        runner(command)
    for item in installs:
        installer(item)
    if not injected:
        for item in installs:
            validate_trusted_execution_path(item.destination)
    for command in commands[preparation_count:]:
        runner(command)
    return SetupReport(applied=True, commands=commands, installs=installs)


def _listening_ports() -> list[int]:
    ports: set[int] = set()
    for proc_file in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = proc_file.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 3 and fields[3] == "0A":
                try:
                    ports.add(int(fields[1].rsplit(":", 1)[1], 16))
                except (IndexError, ValueError):
                    continue
    return sorted(ports)


def _default_runner(argv: Sequence[str]) -> tuple[int, str]:
    try:
        if os.geteuid() == 0:
            _validate_executable(Path(argv[0]))
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, shell=False, check=False, cwd="/", env=_root_environment())
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    output = (result.stdout or result.stderr).strip().splitlines()
    return result.returncode, output[0][:200] if output else ""


def collect_preflight(
    *,
    public_ip: str,
    plugin_port: int,
    runtime_dir: str | os.PathLike[str],
    certificate_path: str | os.PathLike[str] | None = None,
    private_key_path: str | os.PathLike[str] | None = None,
    trust_roots: str | os.PathLike[str] | None = None,
    certbot_executable: str | os.PathLike[str] = CERTBOT,
    command_runner: Callable[[Sequence[str]], tuple[int, str]] | None = None,
) -> dict[str, object]:
    """Collect non-secret local metadata; never infer Internet reachability."""
    ipaddress.ip_address(public_ip)
    if not 1 <= plugin_port <= 65535:
        raise ValueError("plugin_port must be in 1..65535")
    runner = command_runner or _default_runner
    certbot = str(certbot_executable)
    commands = {
        "firewall": ("/usr/sbin/ufw", "status"),
        "renewal_timers": ("/usr/bin/systemctl", "list-timers", "--all", "--no-legend", "--no-pager", "*certbot*"),
        "certbot": (certbot, "--version"),
    }
    command_status = {}
    for name, argv in commands.items():
        code, first_line = runner(argv)
        command_status[name] = {"available": code != 127, "exit_code": code, "summary": first_line}
    root = Path(runtime_dir)
    runtime: dict[str, object] = {"exists": root.exists(), "is_directory": root.is_dir(), "path": str(root)}
    try:
        info = root.stat()
        runtime.update({"mode": f"{info.st_mode & 0o777:04o}", "uid": info.st_uid, "gid": info.st_gid})
    except OSError:
        pass
    certificate: dict[str, object] = {"status": "not_configured"}
    if certificate_path is not None or private_key_path is not None:
        if certificate_path is None or private_key_path is None:
            certificate = {"status": "invalid", "reason": "both certificate and key paths are required"}
        else:
            try:
                metadata = validate_certificate(
                    certificate_path, private_key_path, expected_ip=public_ip, trust_roots=trust_roots
                )
                certificate = {
                    "status": "valid",
                    "ip_sans": list(metadata.ip_sans),
                    "not_after": metadata.not_after.isoformat(),
                    "sha256_fingerprint": metadata.sha256_fingerprint,
                }
            except TLSValidationError as exc:
                certificate = {"status": "invalid", "reason": str(exc)}
    listeners = _listening_ports()
    return {
        "public_ip": public_ip,
        "plugin_port": plugin_port,
        "plugin_port_listening_locally": plugin_port in listeners,
        "listeners": {str(port): port in listeners for port in sorted({80, 443, plugin_port})},
        "commands": command_status,
        "runtime_directory": runtime,
        "certificate": certificate,
        "certbot_executable": certbot if Path(certbot).is_file() else None,
        "external_reachability": {
            "status": "not_checked",
            "reason": "requires a response from an explicitly external vantage",
        },
        "hostname": socket.gethostname(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan/read TLS setup, or explicitly apply it after prerequisites are installed"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true", help="read-only checks (default)")
    mode.add_argument("--apply", action="store_true", help="perform the displayed root setup")
    parser.add_argument("--confirm", help=f"required with --apply: {CONFIRMATION}")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--hermes-user", required=True)
    parser.add_argument("--hermes-group")
    parser.add_argument("--plugin-port", type=int, default=18443)
    parser.add_argument("--email")
    environment = parser.add_mutually_exclusive_group()
    environment.add_argument("--staging", action="store_true", help="request a staging certificate (default)")
    environment.add_argument("--production", action="store_true", help="request production and run renew --dry-run")
    parser.add_argument("--certificate-name")
    parser.add_argument("--certbot-executable", type=Path, default=Path(CERTBOT))
    parser.add_argument("--python-executable", type=Path, default=Path("/usr/bin/python3"))
    parser.add_argument("--helper-install-dir", type=Path, default=_DEFAULT_HELPER_DIR)
    parser.add_argument("--hook-install-path", type=Path, default=_DEFAULT_HOOK)
    parser.add_argument("--trusted-source-root", type=Path, default=Path("/etc/letsencrypt"))
    parser.add_argument("--certificate")
    parser.add_argument("--private-key")
    parser.add_argument("--trust-roots", type=Path)
    parser.add_argument(
        "--renewal-scheduler-verified",
        action="store_true",
        help="assert that an active packaged Certbot renewal scheduler was independently verified",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = SetupConfig(
            public_ip=args.public_ip,
            runtime_dir=args.runtime_dir,
            hermes_user=args.hermes_user,
            hermes_group=args.hermes_group,
            plugin_port=args.plugin_port,
            email=args.email,
            staging=not args.production,
            certificate_name=args.certificate_name,
            certbot_executable=args.certbot_executable,
            python_executable=args.python_executable,
            helper_install_dir=args.helper_install_dir,
            hook_install_path=args.hook_install_path,
            trusted_source_root=args.trusted_source_root,
            trust_roots=args.trust_roots,
            renewal_scheduler_verified=args.renewal_scheduler_verified,
        )
        commands = build_setup_commands(config)
        installs = build_root_installs(config)
        if not args.apply:
            preflight = collect_preflight(
                public_ip=config.public_ip,
                plugin_port=config.plugin_port,
                runtime_dir=config.runtime_dir,
                certificate_path=args.certificate,
                private_key_path=args.private_key,
                trust_roots=args.trust_roots,
                certbot_executable=config.certbot_executable,
            )
            print(json.dumps({
                "mode": "preflight",
                "writes_performed": False,
                "production_ready": False,
                "certificate_environment": "production" if args.production else "staging",
                "normal_renewal_dry_run": "planned_not_executed" if args.production else "not_applicable",
                "planned_commands": commands,
                "planned_root_installs": [
                    {"destination": str(item.destination), "mode": f"{item.mode:04o}"} for item in installs
                ],
                "prerequisites": [
                    "run apply as root only after reviewing this plan",
                    f"provide an existing trusted Certbot executable at {config.certbot_executable}",
                    "ensure public TCP/80 is externally reachable for standalone HTTP-01",
                    "verify an active packaged Certbot renewal scheduler, then pass --renewal-scheduler-verified",
                    f"separately approve any firewall/provider changes needed for TCP/80 and TCP/{config.plugin_port}",
                ],
                "preflight": preflight,
            }, sort_keys=True))
            return 0
        pwd.getpwnam(args.hermes_user)
        report = run_setup(config, apply=True, confirmation=args.confirm)
        print(json.dumps({
            "mode": "apply",
            "applied": report.applied,
            "certificate_environment": "production" if args.production else "staging",
            "production_ready": False,
            "reason": "external HTTPS verification remains required",
            "normal_renewal_dry_run": "executed" if args.production else "not_applicable",
            "installed_root_files": [str(item.destination) for item in report.installs],
        }, sort_keys=True))
        return 0
    except (KeyError, OSError, ValueError, RuntimeError, PermissionError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
