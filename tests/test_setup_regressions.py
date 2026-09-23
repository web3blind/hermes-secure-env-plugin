"""Regression checks for installer recovery and real configured HTTPS ingress."""
from functools import partial
from pathlib import Path
import json
import subprocess
import sys
from urllib.parse import urlsplit

import pytest
import yaml

from scripts import install_host
from secure_env_ingress import setup_config
from secure_env_ingress.runtime import IngressRuntime
from secure_env_ingress.tls import validate_certificate
from test_tls import cert_material
from test_runtime_e2e import post


def test_missing_certbot_real_probe_is_installable(tmp_path):
    assert install_host._certbot_probe(install_host.real_executor, tmp_path / 'absent') == ('missing', None)


def test_command_failure_and_invalid_version_do_not_echo_output():
    sentinel = 'fixture-output-must-not-reach-agent'
    def execute(argv):
        return install_host.CommandResult(1, sentinel, sentinel)
    with pytest.raises(install_host.InstallError) as error:
        install_host._run(execute, ['/usr/bin/false'], code='STEP_FAILED', recovery='retry preflight')
    assert sentinel not in json.dumps(error.value.as_dict())
    assert install_host._certbot_probe(execute, Path('/usr/bin/false')) == ('invalid', None)


def test_direct_installer_help_outside_checkout(tmp_path):
    script = Path(install_host.__file__)
    result = subprocess.run([sys.executable, '-E', '-s', str(script), '--help'], cwd=tmp_path,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert 'PRIVILEGED-HOST-INSTALL' in result.stdout


def test_config_duplicate_keys_refused_without_config_mutation(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    config = home / 'config.yaml'
    original = 'model: first\nmodel: second\n'
    config.write_text(original)
    config.chmod(0o600)
    with pytest.raises(setup_config.SetupConfigError, match='duplicate'):
        setup_config.configure(home=home, owner=88, public_ip='127.0.0.1')
    assert config.read_text() == original


def test_configure_preserves_comments(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    config = home / 'config.yaml'
    config.write_text('# Keep this operator note\nmodel: "example-model" # Keep this too\n')
    config.chmod(0o600)
    setup_config.configure(home=home, owner=88, public_ip='127.0.0.1')
    assert '# Keep this operator note' in config.read_text()
    assert '# Keep this too' in config.read_text()
    assert config.stat().st_mode & 0o777 == 0o600


def test_real_configure_check_https_write(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    # Local-only testing trusts a disposable CA; no production trust override exists in the CLI.
    cert, key, root = cert_material(tmp_path / 'ca')
    monkeypatch.setattr(setup_config, 'validate_certificate', partial(validate_certificate, trust_roots=root))
    import socket
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    report = setup_config.configure(home=home, owner=88, public_ip='127.0.0.1', tls_dir=cert.parent, port=port)
    assert report.ready
    settings = yaml.safe_load((home / 'config.yaml').read_text())['plugins']['entries']['secure-env-ingress']['settings']
    assert not (home / '.env').exists()
    runtime = IngressRuntime(settings, home, '111:offline', trust_roots=root)
    try:
        links = runtime.create(88, 'test')
        token = urlsplit(links['url']).fragment
        code, response = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['made-up-install-check']})
        assert code == 200
        target = home / 'secrets-ingress' / 'test.env'
        assert target.is_file() and target.stat().st_mode & 0o777 == 0o600
        assert not (home / '.env').exists()
        assert 'made-up-install-check' not in repr(response)
    finally:
        runtime.close()
