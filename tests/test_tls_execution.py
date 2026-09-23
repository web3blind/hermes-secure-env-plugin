from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from secure_env_ingress import tls


def _capture_run(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(tls.subprocess, "run", fake_run)
    return calls


def test_unprivileged_verification_uses_absolute_openssl_and_sanitized_process(monkeypatch, tmp_path):
    trust_roots = tmp_path / "offline-root.pem"
    trust_roots.write_text("test root", encoding="utf-8")
    monkeypatch.setattr(tls.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("OPENSSL_CONF", "/tmp/attacker-openssl.cnf")
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/attacker-ca.pem")
    calls = _capture_run(monkeypatch)

    tls._verify_chain([b"leaf certificate"], trust_roots)

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[0] == "/usr/bin/openssl"
    assert command[1:4] == ["verify", "-purpose", "sslserver"]
    assert command[4:6] == ["-CAfile", str(trust_roots.resolve())]
    assert kwargs["env"] == {"LANG": "C", "LC_ALL": "C"}
    assert kwargs["cwd"] == "/"
    assert "OPENSSL_CONF" not in kwargs["env"]
    assert "SSL_CERT_FILE" not in kwargs["env"]


def test_privileged_verification_accepts_root_owned_openssl_ancestry(monkeypatch, tmp_path):
    trust_roots = tmp_path / "offline-root.pem"
    trust_roots.write_text("test root", encoding="utf-8")
    monkeypatch.setattr(tls.os, "geteuid", lambda: 0)
    calls = _capture_run(monkeypatch)

    tls._verify_chain([b"leaf certificate"], trust_roots)

    assert calls[0][0][0] == "/usr/bin/openssl"


def test_privileged_verification_rejects_non_root_owned_executable(monkeypatch, tmp_path):
    fake_openssl = tmp_path / "openssl"
    fake_openssl.write_text("not an executable", encoding="utf-8")
    fake_openssl.chmod(0o755)
    monkeypatch.setattr(tls, "_OPENSSL_PATH", fake_openssl)
    monkeypatch.setattr(tls.os, "geteuid", lambda: 0)
    calls = _capture_run(monkeypatch)

    with pytest.raises(tls.TLSValidationError, match="root-owned"):
        tls._verify_chain([b"leaf certificate"], None)

    assert calls == []


def test_privileged_verification_rejects_writable_resolved_ancestry(monkeypatch, tmp_path):
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o755)
    fake_openssl = unsafe_parent / "openssl"
    fake_openssl.write_text("not an executable", encoding="utf-8")
    fake_openssl.chmod(0o755)
    monkeypatch.setattr(tls, "_OPENSSL_PATH", fake_openssl)
    monkeypatch.setattr(tls.os, "geteuid", lambda: 0)

    real_stat = Path.stat

    def root_owned_stat(path: Path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        values = list(result)
        values[4] = 0
        if path == unsafe_parent:
            values[0] = (result.st_mode & ~0o777) | 0o775
        return os.stat_result(values)

    monkeypatch.setattr(Path, "stat", root_owned_stat)
    calls = _capture_run(monkeypatch)

    with pytest.raises(tls.TLSValidationError, match="writable by group or other"):
        tls._verify_chain([b"leaf certificate"], None)

    assert calls == []
