#!/usr/bin/env python3
"""Deterministic privileged host installer for secure-env TLS.

Safe usage (run this copy only from an independently provisioned, root-owned,
non-writable bundle)::

  /usr/bin/python3 -I -S /trusted/bundle/scripts/install_host.py \
    --preflight --public-ip 203.0.113.10 --runtime-dir /home/hermes/.hermes/tls \
    --hermes-user hermes --trusted-bundle-root /trusted/bundle --profile default

  sudo /usr/bin/python3 -I -S /trusted/bundle/scripts/install_host.py \
    --apply --production --confirm PRIVILEGED-HOST-INSTALL --production-consent ISSUE-PRODUCTION-CERTIFICATE \
    --public-ip 203.0.113.10 --runtime-dir /home/hermes/.hermes/tls \
    --hermes-user hermes --trusted-bundle-root /trusted/bundle --profile default

Preflight is read-only. Apply supports Debian/Ubuntu with apt and snap, installs
missing ``snapd`` and ``python3-venv``, provisions a fixed root-owned virtual
environment with exact Python dependency pins, installs the classic Certbot snap
only when Certbot is absent, verifies its matching systemd renewal timer, and delegates all
certificate issuance/deployment to :mod:`scripts.setup_tls`. Production is
never attempted without its second exact consent token and is always preceded
by staging in the same invocation.

The installer never edits a firewall, stops a service, or resolves a TCP/80
conflict. It cannot prove provider firewall/NAT reachability; those remain
operator checks. Package downloads and ACME are external side effects, so tests
must inject an executor and must not run live apply.
"""

from __future__ import annotations

# Root cannot undo startup hooks already processed by Python. Enforce the
# trusted system bootstrap and isolation flags before importing broad stdlib or
# project modules; operators must invoke this exact entry point directly.
import os
import stat
import sys


def _bootstrap_interpreter_guard() -> None:
    if os.geteuid() != 0:
        return
    if not sys.flags.isolated or not sys.flags.no_site:
        raise PermissionError("root must invoke /usr/bin/python3 -I -S directly")
    executable = os.path.realpath(sys.executable)
    expected = os.path.realpath("/usr/bin/python3")
    if executable != expected:
        raise PermissionError("root bootstrap requires the trusted /usr/bin/python3 interpreter")
    current = os.path.sep
    for part in executable.split(os.path.sep)[1:]:
        current = os.path.join(current, part)
        info = os.lstat(current)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("root bootstrap interpreter path is not root-owned and non-writable")
    info = os.stat(executable)
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise PermissionError("root bootstrap interpreter is not an executable regular file")


def _bootstrap_root_source_guard() -> None:
    """Validate the complete source bundle before broad or project imports."""
    if os.geteuid() != 0:
        return
    target = os.path.abspath(__file__)
    current = os.path.sep
    for part in target.split(os.path.sep)[1:]:
        current = os.path.join(current, part)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(
                f"root refuses untrusted installer source component: {current}; "
                "use an independently provisioned root-owned bundle"
            )
    root = os.path.dirname(os.path.dirname(target))
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            component = os.path.join(directory, name)
            info = os.lstat(component)
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise PermissionError("untrusted bundle component")


_bootstrap_interpreter_guard()
_bootstrap_root_source_guard()

import argparse  # noqa: E402 - privileged bootstrap guards must run first
import ipaddress  # noqa: E402 - privileged bootstrap guards must run first
import json  # noqa: E402 - privileged bootstrap guards must run first
import re  # noqa: E402 - privileged bootstrap guards must run first
import subprocess  # noqa: E402 - privileged bootstrap guards must run first
from dataclasses import dataclass, field  # noqa: E402 - privileged bootstrap guards must run first
from pathlib import Path  # noqa: E402 - privileged bootstrap guards must run first
from typing import Callable, Mapping, Sequence  # noqa: E402 - privileged bootstrap guards must run first


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import setup_tls  # noqa: E402 - validate privileged source before importing

APPLY_CONFIRMATION = "PRIVILEGED-HOST-INSTALL"
PRODUCTION_CONSENT = "ISSUE-PRODUCTION-CERTIFICATE"
APT_GET = Path("/usr/bin/apt-get")
DPKG_QUERY = Path("/usr/bin/dpkg-query")
SYSTEMCTL = Path("/usr/bin/systemctl")
SNAP = Path("/usr/bin/snap")
INSTALL = Path("/usr/bin/install")
DEFAULT_CERTBOT = Path("/snap/bin/certbot")
SYSTEM_PYTHON = Path("/usr/bin/python3")
INSTALLER_VENV = Path("/opt/hermes-secure-env/installer-venv")
DEFAULT_PYTHON = INSTALLER_VENV / "bin" / "python"
INSTALLER_VENV_PACKAGE = "python3-venv"
PINNED_PYTHON_PACKAGES = ("cryptography==50.0.1", "cffi==2.1.1", "pycparser==3.0")
CERTBOT_RENEWAL_UNITS = {DEFAULT_CERTBOT: "snap.certbot.renew.timer"}
_SAFE_PROFILE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
_CERTBOT_VERSION = re.compile(r"(?:certbot\s+)?(\d+)\.(\d+)(?:\.\d+)?", re.IGNORECASE)
_PYTHON_VERIFY_CODE = (
    "import sys; from importlib.metadata import version; "
    "expected={'cryptography':'50.0.1','cffi':'2.1.1','pycparser':'3.0'}; "
    "sys.exit(0 if all(version(name)==wanted for name,wanted in expected.items()) else 1)"
)
_SETUP_TLS_LAUNCHER = (
    "import runpy,sys; "
    "script,root=sys.argv[1:3]; "
    "sys.argv=[script,*sys.argv[3:]]; "
    "sys.path.insert(0,root); "
    "runpy.run_path(script,run_name='__main__')"
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Executor = Callable[[Sequence[str]], CommandResult]


class InstallError(RuntimeError):
    """Safe, typed failure intended for deterministic model recovery."""

    def __init__(self, code: str, message: str, recovery: str, *, command: Sequence[str] | None = None):
        super().__init__(message)
        self.code = code
        self.recovery = recovery
        self.command = tuple(command) if command else None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "code": self.code,
            "message": str(self),
            "recovery": self.recovery,
        }
        if self.command:
            result["command"] = list(self.command)
        return result


@dataclass(frozen=True)
class InstallConfig:
    public_ip: str
    runtime_dir: Path
    hermes_user: str
    trusted_bundle_root: Path
    profile: str = "default"
    hermes_group: str | None = None
    plugin_port: int = 18443
    email: str | None = None
    certbot_executable: Path = DEFAULT_CERTBOT
    python_executable: Path = DEFAULT_PYTHON
    production: bool = False

    @property
    def profile_tag(self) -> str:
        return f"hermes-secure-env-{self.profile}"

    @property
    def helper_install_dir(self) -> Path:
        return Path("/usr/local/libexec/hermes-secure-env") / self.profile

    @property
    def hook_install_path(self) -> Path:
        return Path("/etc/letsencrypt/renewal-hooks/deploy") / self.profile_tag

    @property
    def certificate_name(self) -> str:
        ip_tag = self.public_ip.replace(":", "-").replace(".", "-")
        return f"{self.profile_tag}-{ip_tag}"


@dataclass(frozen=True)
class PreflightReport:
    os_id: str
    os_version: str
    systemd_available: bool
    port_80_available: bool
    packages: Mapping[str, bool]
    certbot_status: str
    certbot_version: str | None
    python_status: str
    renewal_unit: str | None
    renewal_enabled: bool
    renewal_active: bool
    issues: tuple[InstallError, ...] = field(default_factory=tuple)

    @property
    def ready_to_apply(self) -> bool:
        return not self.issues

    def as_dict(self) -> dict[str, object]:
        return {
            "os": {"id": self.os_id, "version_id": self.os_version},
            "systemd_available": self.systemd_available,
            "port_80_available": self.port_80_available,
            "packages": dict(self.packages),
            "certbot": {"status": self.certbot_status, "version": self.certbot_version},
            "python_runtime": {
                "path": str(DEFAULT_PYTHON),
                "status": self.python_status,
                "pinned_packages": list(PINNED_PYTHON_PACKAGES),
            },
            "renewal": {
                "unit": self.renewal_unit,
                "enabled": self.renewal_enabled,
                "active": self.renewal_active,
            },
            "ready_to_apply": self.ready_to_apply,
            "issues": [issue.as_dict() for issue in self.issues],
        }


@dataclass(frozen=True)
class InstallReport:
    applied: bool
    production_applied: bool
    commands: tuple[tuple[str, ...], ...]
    renewal_unit: str


def _validate_absolute(path: Path, label: str) -> None:
    if not path.is_absolute() or any(character in str(path) for character in ("\x00", "\n", "\r")):
        raise InstallError("INVALID_PATH", f"{label} must be a safe absolute path", f"provide an absolute {label}")


def validate_config(config: InstallConfig) -> None:
    try:
        ipaddress.ip_address(config.public_ip)
    except ValueError as exc:
        raise InstallError("INVALID_PUBLIC_IP", "public_ip is not an IP address", "provide the server's literal public IP") from exc
    if not 1 <= config.plugin_port <= 65535:
        raise InstallError("INVALID_PLUGIN_PORT", "plugin_port must be in 1..65535", "choose an unused valid TCP port")
    if not _SAFE_PROFILE.fullmatch(config.profile):
        raise InstallError("INVALID_PROFILE", "profile must match [a-z0-9][a-z0-9-]{0,31}", "use a lowercase profile identifier")
    for label, value in (("hermes_user", config.hermes_user), ("hermes_group", config.hermes_group or config.hermes_user)):
        if not value or value.startswith("-") or any(character.isspace() for character in value):
            raise InstallError("INVALID_ACCOUNT", f"{label} is invalid", "provide an existing non-root runtime account and group")
    for label, path in (
        ("runtime_dir", config.runtime_dir),
        ("trusted_bundle_root", config.trusted_bundle_root),
        ("certbot_executable", config.certbot_executable),
        ("python_executable", config.python_executable),
    ):
        _validate_absolute(path, label)
    if config.certbot_executable != DEFAULT_CERTBOT:
        raise InstallError(
            "UNSUPPORTED_CERTBOT_PATH",
            f"only the classic snap Certbot executable is supported: {DEFAULT_CERTBOT}",
            "use the supported snap executable so renewal provenance is unambiguous",
        )
    if config.python_executable != DEFAULT_PYTHON:
        raise InstallError(
            "UNSUPPORTED_PYTHON_PATH",
            f"the deployment helper requires the managed root-owned interpreter: {DEFAULT_PYTHON}",
            "remove the custom Python path and let apply provision the managed virtual environment",
        )


def _root_environment() -> dict[str, str]:
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C"}


def real_executor(argv: Sequence[str]) -> CommandResult:
    """Run one absolute command with no inherited Python, locale, or loader state."""
    command = tuple(str(part) for part in argv)
    if not command or not Path(command[0]).is_absolute():
        raise InstallError("UNSAFE_COMMAND", "refusing a non-absolute executable", "use an audited absolute executable path")
    if os.geteuid() == 0:
        try:
            setup_tls._validate_executable(Path(command[0]))
        except (OSError, PermissionError, ValueError) as exc:
            raise InstallError(
                "UNTRUSTED_EXECUTABLE",
                f"refusing untrusted privileged executable: {command[0]}",
                "repair the root-owned executable and every path component",
                command=command,
            ) from exc
    try:
        completed = subprocess.run(
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
            cwd="/",
            env=_root_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError("COMMAND_UNAVAILABLE", f"command could not be executed: {command[0]}", "install or repair the named host prerequisite", command=command) from exc
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _run(execute: Executor, argv: Sequence[str], *, code: str, recovery: str) -> CommandResult:
    command = tuple(str(part) for part in argv)
    result = execute(command)
    if result.returncode != 0:
        raise InstallError(code, f"command failed with exit code {result.returncode}", recovery, command=command)
    return result


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InstallError("OS_UNSUPPORTED", "cannot read /etc/os-release", "use a supported Debian or Ubuntu system") from exc
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return values


def _package_installed(execute: Executor, package: str) -> bool:
    result = execute((str(DPKG_QUERY), "-W", "-f=${Status}", package))
    return result.returncode == 0 and result.stdout.strip() == "install ok installed"


def _certbot_probe(execute: Executor, executable: Path) -> tuple[str, str | None]:
    if execute is real_executor and not os.path.lexists(executable):
        return "missing", None
    result = execute((str(executable), "--version"))
    if result.returncode == 127:
        return "missing", None
    output = (result.stdout or result.stderr).strip()
    match = _CERTBOT_VERSION.search(output)
    if result.returncode != 0 or match is None:
        return "invalid", None
    version = f"{match.group(1)}.{match.group(2)}"
    if (int(match.group(1)), int(match.group(2))) < (5, 4):
        return "unsupported", version
    return "verified", version


def _python_probe(execute: Executor, executable: Path) -> str:
    if execute is real_executor and not os.path.lexists(executable):
        return "missing"
    result = execute((str(executable), "-E", "-s", "-c", _PYTHON_VERIFY_CODE))
    if result.returncode == 127:
        return "missing"
    return "verified" if result.returncode == 0 else "dependencies-mismatch"


def _systemd_available(execute: Executor) -> bool:
    result = execute((str(SYSTEMCTL), "show", "--property=Version", "--value"))
    return result.returncode == 0


def _unit_state(execute: Executor, unit: str) -> tuple[bool, bool, bool]:
    loaded = execute((str(SYSTEMCTL), "show", "--property=LoadState", "--value", unit))
    if loaded.returncode != 0 or loaded.stdout.strip() != "loaded":
        return False, False, False
    enabled = execute((str(SYSTEMCTL), "is-enabled", "--quiet", unit)).returncode == 0
    active = execute((str(SYSTEMCTL), "is-active", "--quiet", unit)).returncode == 0
    return True, enabled, active


def _renewal_state(execute: Executor, certbot_executable: Path) -> tuple[str | None, bool, bool]:
    unit = CERTBOT_RENEWAL_UNITS.get(certbot_executable)
    if unit is None:
        return None, False, False
    loaded, enabled, active = _unit_state(execute, unit)
    return (unit, enabled, active) if loaded else (None, False, False)


def collect_preflight(
    config: InstallConfig,
    *,
    execute: Executor = real_executor,
    os_release: Mapping[str, str] | None = None,
    listening_ports: Sequence[int] | None = None,
) -> PreflightReport:
    """Read host state only. The injected seams perform no implicit mutation."""
    validate_config(config)
    if execute is real_executor and os.path.lexists(INSTALLER_VENV):
        try:
            # Do not start an existing interpreter until every entry in its
            # environment (including site-packages and .pth files) is trusted.
            _validate_managed_venv(require_python=True)
        except (OSError, PermissionError, ValueError) as exc:
            raise InstallError(
                "UNTRUSTED_PYTHON_ENVIRONMENT",
                "existing managed Python virtual environment failed root trust validation",
                f"remove or repair {INSTALLER_VENV} outside this installer, then rerun preflight",
            ) from exc
    release = dict(os_release) if os_release is not None else _read_os_release()
    os_id = release.get("ID", "").lower()
    os_version = release.get("VERSION_ID", "")
    systemd = _systemd_available(execute)
    ports = set(listening_ports if listening_ports is not None else setup_tls._listening_ports())
    packages = {
        "snapd": _package_installed(execute, "snapd"),
        INSTALLER_VENV_PACKAGE: _package_installed(execute, INSTALLER_VENV_PACKAGE),
    }
    certbot_status, certbot_version = _certbot_probe(execute, config.certbot_executable)
    python_status = _python_probe(execute, config.python_executable)
    renewal_unit, renewal_enabled, renewal_active = _renewal_state(execute, config.certbot_executable) if systemd else (None, False, False)
    issues: list[InstallError] = []
    if os_id not in {"debian", "ubuntu"}:
        issues.append(InstallError("OS_UNSUPPORTED", f"unsupported operating system: {os_id or 'unknown'}", "use Debian/Ubuntu or perform a separately reviewed manual installation"))
    if not systemd:
        issues.append(InstallError("SYSTEMD_REQUIRED", "systemd is not available as the service manager", "run on a systemd host; this installer will not emulate renewal scheduling"))
    if 80 in ports:
        issues.append(InstallError("PORT_80_IN_USE", "TCP/80 already has a local listener", "move or reconfigure the listener yourself, then rerun preflight; the installer will not stop it"))
    if certbot_status in {"invalid", "unsupported"}:
        issues.append(InstallError("CERTBOT_UNSUPPORTED", f"existing Certbot is {certbot_status}: {certbot_version or 'unknown'}", "provide a trusted Certbot >= 5.4 path; an existing invalid binary is never replaced automatically"))
    return PreflightReport(
        os_id=os_id,
        os_version=os_version,
        systemd_available=systemd,
        port_80_available=80 not in ports,
        packages=packages,
        certbot_status=certbot_status,
        certbot_version=certbot_version,
        python_status=python_status,
        renewal_unit=renewal_unit,
        renewal_enabled=renewal_enabled,
        renewal_active=renewal_active,
        issues=tuple(issues),
    )


def _require_trusted_bundle(config: InstallConfig) -> None:
    root = config.trusted_bundle_root.resolve(strict=True)
    current = Path(__file__).resolve(strict=True)
    required = (
        current,
        root / "scripts" / "setup_tls.py",
        root / "scripts" / "deploy_certificate.py",
        root / "secure_env_ingress" / "__init__.py",
        root / "secure_env_ingress" / "tls.py",
    )
    try:
        current.relative_to(root)
    except ValueError as exc:
        raise InstallError("UNTRUSTED_BUNDLE", "running installer is outside trusted_bundle_root", "invoke the installer from the independently provisioned root-owned bundle") from exc
    try:
        for source in required:
            setup_tls.validate_trusted_execution_path(source)
        # Root must never import this installer through a runtime-user-owned
        # Python, even when every source file in the bundle is trusted.
        setup_tls._validate_executable(Path(sys.executable))
    except (OSError, PermissionError, ValueError) as exc:
        raise InstallError("UNTRUSTED_BUNDLE", "trusted root source/interpreter validation failed", "provision a root-owned, non-writable bundle and interpreter independently of the runtime user") from exc


def _validate_managed_venv(*, require_python: bool) -> None:
    """Reject a pre-existing managed path unless its complete tree is root-trusted."""
    ancestor = setup_tls._trusted_existing_ancestor(INSTALLER_VENV)
    if ancestor.is_file() or ancestor.is_symlink():
        raise PermissionError("managed Python path has a non-directory ancestor")
    setup_tls._validate_trusted_directory(ancestor)
    if not INSTALLER_VENV.exists():
        if require_python:
            raise PermissionError("managed Python virtual environment is missing")
        return
    setup_tls._validate_trusted_directory(INSTALLER_VENV)
    for directory, dirs, files in os.walk(INSTALLER_VENV, followlinks=False):
        for name in (*dirs, *files):
            component = Path(directory) / name
            info = component.lstat()
            if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022):
                raise PermissionError("managed Python virtual environment is not root-owned and non-writable")
            if stat.S_ISLNK(info.st_mode):
                resolved = component.resolve(strict=True)
                if resolved.is_file():
                    setup_tls.validate_trusted_execution_path(resolved)
                else:
                    setup_tls._validate_trusted_directory(resolved)
    if require_python:
        setup_tls._validate_executable(DEFAULT_PYTHON)


def _tls_config(config: InstallConfig, *, staging: bool) -> setup_tls.SetupConfig:
    root = config.trusted_bundle_root.resolve()
    return setup_tls.SetupConfig(
        public_ip=config.public_ip,
        runtime_dir=config.runtime_dir,
        hermes_user=config.hermes_user,
        hermes_group=config.hermes_group,
        plugin_port=config.plugin_port,
        email=config.email,
        staging=staging,
        certificate_name=config.certificate_name,
        certbot_executable=config.certbot_executable,
        python_executable=config.python_executable,
        deploy_helper_source=root / "scripts" / "deploy_certificate.py",
        package_init_source=root / "secure_env_ingress" / "__init__.py",
        tls_helper_source=root / "secure_env_ingress" / "tls.py",
        helper_install_dir=config.helper_install_dir,
        hook_install_path=config.hook_install_path,
        renewal_scheduler_verified=True,
    )


def _run_managed_tls_setup(
    config: InstallConfig,
    *,
    staging: bool,
    execute: Executor = real_executor,
) -> CommandResult:
    """Execute the hardened setup CLI using the validated managed Python tree."""
    root = config.trusted_bundle_root.resolve()
    command: list[str] = [
        str(config.python_executable),
        "-I",
        "-c",
        _SETUP_TLS_LAUNCHER,
        str(root / "scripts" / "setup_tls.py"),
        str(root),
        "--apply",
        "--confirm",
        setup_tls.CONFIRMATION,
        "--public-ip",
        config.public_ip,
        "--runtime-dir",
        str(config.runtime_dir),
        "--hermes-user",
        config.hermes_user,
        "--plugin-port",
        str(config.plugin_port),
        "--certificate-name",
        config.certificate_name,
        "--certbot-executable",
        str(config.certbot_executable),
        "--python-executable",
        str(config.python_executable),
        "--helper-install-dir",
        str(config.helper_install_dir),
        "--hook-install-path",
        str(config.hook_install_path),
        "--renewal-scheduler-verified",
        "--staging" if staging else "--production",
    ]
    if config.hermes_group is not None:
        command.extend(("--hermes-group", config.hermes_group))
    if config.email is not None:
        command.extend(("--email", config.email))
    return _run(
        execute,
        command,
        code="TLS_SETUP_COMMAND_FAILED",
        recovery="inspect the safe Certbot diagnostic, correct DNS/network/ACME prerequisites, and rerun",
    )


def _ensure_renewal(execute: Executor, certbot_executable: Path) -> str:
    unit, enabled, active = _renewal_state(execute, certbot_executable)
    if unit is None:
        raise InstallError("RENEWAL_UNIT_MISSING", "no packaged Certbot renewal timer is loaded", "repair the Certbot package/snap so its systemd timer is present")
    if not enabled or not active:
        _run(execute, (str(SYSTEMCTL), "enable", "--now", unit), code="RENEWAL_ENABLE_FAILED", recovery="repair the packaged Certbot systemd timer and rerun apply")
    loaded, enabled, active = _unit_state(execute, unit)
    if not loaded or not enabled or not active:
        raise InstallError("RENEWAL_NOT_READY", f"renewal timer {unit} is not loaded, enabled, and active", "repair the timer; certificate setup will not continue without automatic renewal")
    return unit


def run_install(
    config: InstallConfig,
    *,
    preflight: PreflightReport,
    apply: bool = False,
    confirmation: str | None = None,
    production_consent: str | None = None,
    execute: Executor = real_executor,
    setup_runner: Callable[..., object] = setup_tls.run_setup,
    trusted_apply: bool = False,
) -> InstallReport:
    """Apply a previously displayed plan; all OS calls cross ``execute``.

    ``trusted_apply`` is solely the unprivileged test seam. The real CLI never
    sets it and therefore always enforces uid 0 and root-owned source checks.
    """
    validate_config(config)
    if not apply:
        return InstallReport(False, False, (), preflight.renewal_unit or "not-yet-installed")
    if confirmation != APPLY_CONFIRMATION:
        raise InstallError("CONFIRMATION_REQUIRED", f"apply requires exact confirmation token {APPLY_CONFIRMATION}", "review preflight, then pass the exact token")
    if config.production and production_consent != PRODUCTION_CONSENT:
        raise InstallError("PRODUCTION_CONSENT_REQUIRED", f"production issuance requires exact token {PRODUCTION_CONSENT}", "first review staging intent, then explicitly consent to the public ACME request")
    if preflight.issues:
        first = preflight.issues[0]
        raise InstallError(first.code, str(first), first.recovery)
    if not trusted_apply:
        if os.geteuid() != 0:
            raise InstallError("ROOT_REQUIRED", "apply must run as root", "rerun the reviewed trusted-bundle command through sudo")
        _require_trusted_bundle(config)

    commands: list[tuple[str, ...]] = []

    def apply_command(argv: Sequence[str], *, code: str, recovery: str) -> CommandResult:
        command = tuple(str(part) for part in argv)
        result = _run(execute, command, code=code, recovery=recovery)
        commands.append(command)
        return result

    missing_packages = [name for name in ("snapd", INSTALLER_VENV_PACKAGE) if not preflight.packages.get(name, False)]
    if missing_packages:
        apply_command((str(APT_GET), "update"), code="APT_UPDATE_FAILED", recovery="repair Debian/Ubuntu apt repositories, then rerun preflight")
        apply_command((str(APT_GET), "install", "--yes", "--no-install-recommends", *missing_packages), code="APT_INSTALL_FAILED", recovery="repair apt/dpkg, then rerun preflight")
    if not preflight.packages.get("snapd", False):
        apply_command((str(SYSTEMCTL), "enable", "--now", "snapd.socket"), code="SNAPD_START_FAILED", recovery="repair the snapd package and socket, then rerun preflight")
    if preflight.certbot_status == "missing":
        apply_command((str(SNAP), "install", "certbot", "--classic"), code="CERTBOT_INSTALL_FAILED", recovery="repair snapd/network access, then rerun preflight")

    certbot_status, version = _certbot_probe(execute, config.certbot_executable)
    if certbot_status != "verified":
        raise InstallError("CERTBOT_VERIFICATION_FAILED", f"Certbot >= 5.4 verification failed after installation: {version or certbot_status}", "repair the trusted Certbot installation; TLS setup was not started")
    if not trusted_apply:
        try:
            _validate_managed_venv(require_python=False)
        except (OSError, PermissionError, ValueError) as exc:
            raise InstallError(
                "UNTRUSTED_PYTHON_ENVIRONMENT",
                "managed Python location is not root-owned and non-writable",
                f"remove or repair {INSTALLER_VENV} outside this installer, then rerun apply",
            ) from exc
    apply_command(
        (str(INSTALL), "-d", "-m", "0755", "-o", "root", "-g", "root", str(INSTALLER_VENV.parent)),
        code="PYTHON_VENV_DIRECTORY_FAILED",
        recovery="repair the root-owned /opt installation directory, then rerun apply",
    )
    if preflight.python_status == "missing":
        apply_command(
            (str(SYSTEM_PYTHON), "-E", "-s", "-m", "venv", str(INSTALLER_VENV)),
            code="PYTHON_VENV_CREATE_FAILED",
            recovery="repair python3-venv, then rerun apply",
        )
    if not trusted_apply:
        try:
            _validate_managed_venv(require_python=True)
        except (OSError, PermissionError, ValueError) as exc:
            raise InstallError(
                "UNTRUSTED_PYTHON_ENVIRONMENT",
                "managed Python virtual environment failed root trust validation",
                f"remove or repair {INSTALLER_VENV} outside this installer, then rerun apply",
            ) from exc
    if preflight.python_status != "verified":
        apply_command(
            (
                str(config.python_executable), "-E", "-s", "-m", "pip", "install",
                "--disable-pip-version-check", "--no-input", "--only-binary=:all:", "--no-deps",
                *PINNED_PYTHON_PACKAGES,
            ),
            code="PYTHON_DEPENDENCY_INSTALL_FAILED",
            recovery="repair package-network access for the exact binary-wheel pins, then rerun apply",
        )
    if not trusted_apply:
        try:
            _validate_managed_venv(require_python=True)
        except (OSError, PermissionError, ValueError) as exc:
            raise InstallError(
                "UNTRUSTED_PYTHON_ENVIRONMENT",
                "installed Python dependency tree failed root trust validation",
                f"remove or repair {INSTALLER_VENV} outside this installer, then rerun apply",
            ) from exc
    python_check = (str(config.python_executable), "-E", "-s", "-c", _PYTHON_VERIFY_CODE)
    apply_command(python_check, code="PYTHON_DEPENDENCY_UNTRUSTED", recovery="repair the exact pinned dependencies in the managed root-owned interpreter")
    renewal_unit = _ensure_renewal(execute, config.certbot_executable)

    def tls_execute(argv: Sequence[str]) -> object:
        command = tuple(str(part) for part in argv)
        result = _run(execute, command, code="TLS_SETUP_COMMAND_FAILED", recovery="inspect the safe Certbot diagnostic, correct DNS/network/ACME prerequisites, and rerun")
        commands.append(command)
        return result

    # setup_tls remains the sole implementation of hardened source installation,
    # certificate issuance, uid-drop deployment, and renewal dry-run behavior.
    staging_config = _tls_config(config, staging=True)
    if trusted_apply:
        setup_runner(
            staging_config,
            apply=True,
            confirmation=setup_tls.CONFIRMATION,
            execute=tls_execute,
            install=lambda item: None,
        )
    elif execute is real_executor and setup_runner is setup_tls.run_setup:
        _run_managed_tls_setup(config, staging=True, execute=execute)
    else:
        # Compatibility for the existing command-boundary test seam. The real
        # CLI always uses real_executor and therefore takes the managed handoff.
        setup_runner(staging_config, apply=True, confirmation=setup_tls.CONFIRMATION)
    if config.production:
        production_config = _tls_config(config, staging=False)
        if trusted_apply:
            setup_runner(
                production_config,
                apply=True,
                confirmation=setup_tls.CONFIRMATION,
                execute=tls_execute,
                install=lambda item: None,
            )
        elif execute is real_executor and setup_runner is setup_tls.run_setup:
            _run_managed_tls_setup(config, staging=False, execute=execute)
        else:
            setup_runner(production_config, apply=True, confirmation=setup_tls.CONFIRMATION)
    return InstallReport(True, config.production, tuple(commands), renewal_unit)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only secure-env host preflight or explicit Debian/Ubuntu apt/snap + staged TLS installation",
        epilog=(
            "Apply never changes firewall rules or stops a TCP/80 listener. Production requires "
            f"--production-consent {PRODUCTION_CONSENT} and always runs staging first."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true", help="read-only host checks (default)")
    mode.add_argument("--apply", action="store_true", help="perform reviewed package and TLS setup")
    parser.add_argument("--confirm", help=f"required for apply: {APPLY_CONFIRMATION}")
    parser.add_argument("--production", action="store_true", help="after staging, request production certificate and renewal dry-run")
    parser.add_argument("--production-consent", help=f"required with --production apply: {PRODUCTION_CONSENT}")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--hermes-user", required=True)
    parser.add_argument("--hermes-group")
    parser.add_argument("--trusted-bundle-root", type=Path, required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--plugin-port", type=int, default=18443)
    parser.add_argument("--email")
    parser.add_argument("--certbot-executable", type=Path, default=DEFAULT_CERTBOT)
    parser.add_argument("--python-executable", type=Path, default=DEFAULT_PYTHON)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = InstallConfig(
            public_ip=args.public_ip,
            runtime_dir=args.runtime_dir,
            hermes_user=args.hermes_user,
            hermes_group=args.hermes_group,
            trusted_bundle_root=args.trusted_bundle_root,
            profile=args.profile,
            plugin_port=args.plugin_port,
            email=args.email,
            certbot_executable=args.certbot_executable,
            python_executable=args.python_executable,
            production=args.production,
        )
        preflight = collect_preflight(config)
        if not args.apply:
            print(json.dumps({
                "mode": "preflight",
                "writes_performed": False,
                "production_requested": config.production,
                "required_apply_confirmation": APPLY_CONFIRMATION,
                "required_production_consent": PRODUCTION_CONSENT if config.production else None,
                "profile_paths": {
                    "helper_install_dir": str(config.helper_install_dir),
                    "hook_install_path": str(config.hook_install_path),
                    "staging_lineage": _tls_config(config, staging=True).effective_certificate_name,
                    "production_lineage": _tls_config(config, staging=False).effective_certificate_name,
                },
                "caveats": [
                    "public TCP/80 reachability from an external vantage is not checked",
                    "firewall and existing services are never changed",
                    "apply performs package downloads and ACME requests",
                ],
                "preflight": preflight.as_dict(),
            }, sort_keys=True))
            return 0
        report = run_install(
            config,
            preflight=preflight,
            apply=True,
            confirmation=args.confirm,
            production_consent=args.production_consent,
        )
        print(json.dumps({
            "mode": "apply",
            "applied": report.applied,
            "staging_applied": report.applied,
            "production_applied": report.production_applied,
            "renewal_unit": report.renewal_unit,
            "external_https_verification_required": True,
        }, sort_keys=True))
        return 0
    except InstallError as exc:
        print(json.dumps({"mode": "error", "error": exc.as_dict()}, sort_keys=True), file=sys.stderr)
        return 2
    except (KeyError, OSError, ValueError, RuntimeError, PermissionError, subprocess.SubprocessError):
        error = InstallError("INSTALL_FAILED", "host or TLS installation failed", "rerun read-only preflight; diagnose without exposing logs or secrets")
        print(json.dumps({"mode": "error", "error": error.as_dict()}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
