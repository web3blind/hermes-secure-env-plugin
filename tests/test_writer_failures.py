import errno
import hashlib
import io
import os
import pytest
from dotenv import dotenv_values
from secure_env_ingress import writer


def test_export_and_multiline_keys_are_not_overwritten(tmp_path):
    target = tmp_path / '.env'
    target.write_text("export OLD='first\nINNER=not-a-key'\n")
    target.chmod(0o600)
    bound = writer.bind_target(target, expected_uid=os.getuid())
    result = writer.add_missing(target, {'OLD': 'fixture', 'INNER': 'other'}, binding=bound)
    assert result.skipped == ('OLD',)
    assert result.added == ('INNER',)


def test_quoted_values_roundtrip_without_printing(tmp_path):
    value = 'line\nquote\"back\\tab\tunicode-λ'
    encoded = writer.quote_dotenv(value)
    parsed = dotenv_values(stream=io.StringIO('KEY='+encoded), interpolate=False)['KEY']
    assert parsed is not None
    assert hashlib.sha256(parsed.encode()).digest() == hashlib.sha256(value.encode()).digest()


@pytest.mark.parametrize('kind', ['fifo', 'hardlink'])
def test_nonordinary_files_refused_without_blocking(tmp_path, kind):
    target = tmp_path / '.env'
    if kind == 'fifo':
        os.mkfifo(target, 0o600)
    else:
        target.touch(mode=0o600)
        os.link(target, tmp_path / 'other')
    with pytest.raises(writer.InsecureTargetError):
        writer.bind_target(target, expected_uid=os.getuid())


def test_full_disk_retains_original_and_cleans_temporary(tmp_path, monkeypatch):
    target = tmp_path / '.env'
    target.write_text('OLD=fixture\n')
    target.chmod(0o600)
    binding = writer.bind_target(target, expected_uid=os.getuid())
    before = hashlib.sha256(target.read_bytes()).digest()
    def fail(*args):
        raise OSError(errno.ENOSPC, 'no space')
    monkeypatch.setattr(writer.os, 'write', fail)
    with pytest.raises(OSError):
        writer.add_missing(target, {'NEW': 'fixture'}, binding=binding)
    assert hashlib.sha256(target.read_bytes()).digest() == before
    assert not list(tmp_path.glob('.*.tmp-*'))
