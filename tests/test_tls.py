from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from secure_env_ingress.tls import TLSValidationError, create_server_ssl_context, validate_certificate

UTC = dt.timezone.utc


def _cert(subject, issuer, public_key, issuer_key, *, ca=False, ip=None, not_before=None, not_after=None):
    now = dt.datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(minutes=5))
        .not_valid_after(not_after or now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ip is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def cert_material(tmp_path: Path, *, ip="127.0.0.1", expired=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert("test root", "test root", root_key.public_key(), root_key, ca=True)
    now = dt.datetime.now(UTC)
    leaf = _cert(
        ip,
        "test root",
        leaf_key.public_key(),
        root_key,
        ip=ip,
        not_before=now - dt.timedelta(days=2) if expired else None,
        not_after=now - dt.timedelta(days=1) if expired else None,
    )
    cert_path = tmp_path / "fullchain.pem"
    key_path = tmp_path / "privkey.pem"
    root_path = tmp_path / "root.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)
    os.chmod(key_path, 0o600)
    return cert_path, key_path, root_path


def test_validate_certificate_accepts_trusted_ip_san_and_matching_key(tmp_path):
    cert, key, root = cert_material(tmp_path)
    result = validate_certificate(cert, key, expected_ip="127.0.0.1", trust_roots=root)
    assert result.ip_sans == ("127.0.0.1",)
    assert result.seconds_remaining > 3600


@pytest.mark.parametrize("failure", ["wrong_ip", "expired", "wrong_key", "untrusted", "key_mode"])
def test_validate_certificate_fails_closed(tmp_path, failure):
    cert, key, root = cert_material(tmp_path, expired=failure == "expired")
    expected_ip = "127.0.0.2" if failure == "wrong_ip" else "127.0.0.1"
    if failure == "wrong_key":
        _, other_key, _ = cert_material(tmp_path / "other")
        key = other_key
    elif failure == "untrusted":
        _, _, root = cert_material(tmp_path / "other")
    elif failure == "key_mode":
        os.chmod(key, 0o644)
    with pytest.raises(TLSValidationError):
        validate_certificate(cert, key, expected_ip=expected_ip, trust_roots=root)


def test_default_ssl_context_serves_without_sni(tmp_path):
    cert, key, root = cert_material(tmp_path)
    context = create_server_ssl_context(cert, key, expected_ip="127.0.0.1", trust_roots=root)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors = []

    def serve():
        try:
            raw, _ = listener.accept()
            with context.wrap_socket(raw, server_side=True) as conn:
                conn.recv(1)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve)
    thread.start()
    client_ctx = ssl.create_default_context(cafile=str(root))
    client_ctx.check_hostname = False
    with socket.create_connection(("127.0.0.1", port)) as raw:
        with client_ctx.wrap_socket(raw, server_hostname=None) as conn:
            assert conn.version() == "TLSv1.3"
            conn.sendall(b"x")
    thread.join(timeout=3)
    assert not errors
