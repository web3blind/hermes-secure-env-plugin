"""Exercise trusted reads with a disposable ownership boundary; never run as root."""
import dataclasses
import os
from pathlib import Path

import pytest
from scripts.setup_tls import SetupConfig, _read_trusted_source, build_deploy_wrapper, build_setup_commands


def read(path, root):
    return _read_trusted_source(path, trusted_uid=os.getuid(), boundary=root)


def test_source_read_and_unsafe_variants(tmp_path):
    root = tmp_path / 'trusted'
    root.mkdir(mode=0o700)
    source = root / 'helper.py'
    source.write_bytes(b'reviewed source')
    source.chmod(0o600)
    assert read(source, root) == b'reviewed source'
    source.chmod(0o666)
    with pytest.raises(PermissionError):
        read(source, root)
    source.chmod(0o600)
    link = root / 'alias'
    link.symlink_to(source)
    with pytest.raises(OSError):
        read(link, root)
    link.unlink()
    os.link(source, link)
    with pytest.raises(PermissionError):
        read(source, root)
    link.unlink()
    root.chmod(0o777)
    with pytest.raises(PermissionError):
        read(source, root)
    root.chmod(0o700)


def test_source_descriptor_survives_name_substitution(tmp_path, monkeypatch):
    source = tmp_path / 'source.py'
    source.write_bytes(b'original')
    source.chmod(0o600)
    original_open = os.open
    def swapping_open(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if path == 'source.py':
            source.rename(tmp_path / 'pinned.py')
            source.write_bytes(b'substitute')
        return fd
    monkeypatch.setattr(os, 'open', swapping_open)
    assert read(source, tmp_path) == b'original'


def test_staging_never_runs_directory_hooks_and_production_never_uses_test_roots():
    cfg = SetupConfig('203.0.113.5', Path('/home/runtime/tls'), 'runtime', trust_roots=Path('/test/roots'))
    issuance = build_setup_commands(cfg)[0]
    assert '--staging' in issuance and '--no-directory-hooks' in issuance
    production = dataclasses.replace(cfg, staging=False)
    assert b'--trust-roots' not in build_deploy_wrapper(production)
    renewal = build_setup_commands(production)[-1]
    assert '--cert-name' in renewal and production.effective_certificate_name in renewal
    assert '--no-directory-hooks' in renewal
