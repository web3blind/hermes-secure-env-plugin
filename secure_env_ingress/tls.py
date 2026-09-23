"""Fail-closed TLS certificate validation for the secure environment ingress."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import ssl
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

class TLSValidationError(ValueError):
    """Certificate material is unsafe or unsuitable for the ingress."""


@dataclass(frozen=True)
class CertificateMetadata:
    subject: str
    issuer: str
    serial_number: int
    ip_sans: tuple[str, ...]
    not_before: dt.datetime
    not_after: dt.datetime
    seconds_remaining: int
    sha256_fingerprint: str


_PEM_CERT = re.compile(
    br"-----BEGIN CERTIFICATE-----\s+.+?-----END CERTIFICATE-----\s*", re.DOTALL
)
_OPENSSL_PATH = Path("/usr/bin/openssl")
_OPENSSL_ENV = {"LANG": "C", "LC_ALL": "C"}


def _regular_file(path: Path, *, mode: int, owner_uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise TLSValidationError(f"cannot inspect {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise TLSValidationError(f"certificate material must be a regular non-symlink file: {path}")
    actual_mode = stat.S_IMODE(info.st_mode)
    if actual_mode != mode:
        raise TLSValidationError(f"unsafe mode for {path}: expected {mode:04o}, got {actual_mode:04o}")
    if info.st_uid != owner_uid:
        raise TLSValidationError(f"wrong owner for {path}: expected uid {owner_uid}, got {info.st_uid}")


def _validate_privileged_executable(path: Path) -> None:
    """Require a root-owned, non-writable executable and resolved ancestry."""
    try:
        resolved = path.resolve(strict=True)
        entries = (resolved, *resolved.parents)
        for entry in entries:
            info = entry.stat()
            if info.st_uid != 0:
                raise TLSValidationError(f"privileged executable ancestry is not root-owned: {entry}")
            if stat.S_IMODE(info.st_mode) & 0o022:
                raise TLSValidationError(
                    f"privileged executable ancestry is writable by group or other: {entry}"
                )
        executable_info = resolved.stat()
        if not stat.S_ISREG(executable_info.st_mode) or not executable_info.st_mode & 0o111:
            raise TLSValidationError(f"privileged OpenSSL path is not an executable regular file: {resolved}")
    except TLSValidationError:
        raise
    except OSError as exc:
        raise TLSValidationError(f"cannot validate privileged OpenSSL executable {path}: {exc}") from exc


def _verify_chain(certificates: list[bytes], trust_roots: Path | None) -> None:
    if os.geteuid() == 0:
        _validate_privileged_executable(_OPENSSL_PATH)
    command = [str(_OPENSSL_PATH), "verify", "-purpose", "sslserver"]
    temporary_path: str | None = None
    leaf_path: str | None = None
    try:
        if trust_roots is not None:
            command.extend(["-CAfile", str(trust_roots.resolve(strict=True))])
        else:
            command.append("-trusted_first")
        if len(certificates) > 1:
            with tempfile.NamedTemporaryFile(prefix="senv-chain-", suffix=".pem", delete=False) as handle:
                handle.write(b"".join(certificates[1:]))
                temporary_path = handle.name
            os.chmod(temporary_path, 0o600)
            command.extend(["-untrusted", temporary_path])
        with tempfile.NamedTemporaryFile(prefix="senv-leaf-", suffix=".pem", delete=False) as handle:
            handle.write(certificates[0])
            leaf_path = handle.name
        os.chmod(leaf_path, 0o600)
        command.append(leaf_path)
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=_OPENSSL_ENV,
            cwd="/",
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise TLSValidationError(f"certificate chain verification failed: {detail}")
    except (OSError, subprocess.SubprocessError) as exc:
        raise TLSValidationError(f"certificate chain verification could not run: {exc}") from exc
    finally:
        if temporary_path:
            Path(temporary_path).unlink(missing_ok=True)
        if leaf_path:
            Path(leaf_path).unlink(missing_ok=True)


def validate_certificate(
    certificate_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    *,
    expected_ip: str,
    trust_roots: str | os.PathLike[str] | None = None,
    owner_uid: int | None = None,
    now: dt.datetime | None = None,
    minimum_remaining: dt.timedelta = dt.timedelta(hours=1),
) -> CertificateMetadata:
    """Validate ownership, modes, chain, key match, validity, and exact IP SAN."""
    # Keep module import stdlib-only so bootstrap/preflight can run before the
    # installer provisions its pinned managed interpreter.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    cert_path = Path(certificate_path)
    key_path = Path(private_key_path)
    uid = os.geteuid() if owner_uid is None else owner_uid
    _regular_file(cert_path, mode=0o644, owner_uid=uid)
    _regular_file(key_path, mode=0o600, owner_uid=uid)
    if trust_roots is not None:
        root_path = Path(trust_roots)
        try:
            if not root_path.is_file():
                raise TLSValidationError(f"trust roots are not a regular file: {root_path}")
        except OSError as exc:
            raise TLSValidationError(f"cannot inspect trust roots: {exc}") from exc
    else:
        root_path = None

    try:
        cert_bytes = cert_path.read_bytes()
        key_bytes = key_path.read_bytes()
        blocks = _PEM_CERT.findall(cert_bytes)
        if not blocks:
            raise TLSValidationError("certificate file has no PEM certificate")
        leaf = x509.load_pem_x509_certificate(blocks[0])
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except TLSValidationError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise TLSValidationError(f"cannot parse certificate material: {exc}") from exc

    cert_public = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_public != key_public:
        raise TLSValidationError("private key does not match leaf certificate")

    try:
        expected = ipaddress.ip_address(expected_ip)
    except ValueError as exc:
        raise TLSValidationError(f"expected_ip is not an IP address: {expected_ip}") from exc
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ip_addresses = tuple(str(value) for value in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        ip_addresses = ()
    if str(expected) not in ip_addresses:
        raise TLSValidationError(f"leaf certificate lacks required IP SAN {expected}")

    checked_at = now or dt.datetime.now(dt.timezone.utc)
    if checked_at.tzinfo is None:
        raise TLSValidationError("now must be timezone-aware")
    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if checked_at < not_before:
        raise TLSValidationError("leaf certificate is not yet valid")
    if not_after - checked_at < minimum_remaining:
        raise TLSValidationError("leaf certificate is expired or too close to expiry")

    _verify_chain(blocks, root_path)
    return CertificateMetadata(
        subject=leaf.subject.rfc4514_string(),
        issuer=leaf.issuer.rfc4514_string(),
        serial_number=leaf.serial_number,
        ip_sans=ip_addresses,
        not_before=not_before,
        not_after=not_after,
        seconds_remaining=int((not_after - checked_at).total_seconds()),
        sha256_fingerprint=leaf.fingerprint(hashes.SHA256()).hex(),
    )


def create_server_ssl_context(
    certificate_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    *,
    expected_ip: str,
    trust_roots: str | os.PathLike[str] | None = None,
    owner_uid: int | None = None,
) -> ssl.SSLContext:
    """Return a default-certificate server context that does not require SNI."""
    validate_certificate(
        certificate_path,
        private_key_path,
        expected_ip=expected_ip,
        trust_roots=trust_roots,
        owner_uid=owner_uid,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate_path), str(private_key_path))
    return context
