"""Security regressions for setup boundaries without privileged execution."""
import dataclasses
import os
import sys
import json
import subprocess
from pathlib import Path

import pytest

from scripts import setup_tls
from scripts.deploy_certificate import DeployError, deploy_certificate
from secure_env_ingress.runtime import IngressRuntime


def config(**kwargs):
    return setup_tls.SetupConfig(public_ip='203.0.113.10', hermes_user='runtime', runtime_dir=Path('/home/runtime/tls'), staging=False, **kwargs)


def test_root_preparation_never_writes_runtime_account_tree():
    cfg = config()
    assert all(str(cfg.runtime_dir) not in command for command in setup_tls._preparation_commands(cfg))


def test_staging_is_distinct_and_installs_no_production_hook():
    production = config()
    staging = dataclasses.replace(production, staging=True)
    report = setup_tls.run_setup(staging)
    assert report.installs == ()
    assert staging.effective_certificate_name != production.effective_certificate_name
    assert len(report.commands) == 1


def test_root_runtime_is_refused(monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    with pytest.raises(RuntimeError, match='non-root'):
        IngressRuntime({}, Path('/unused'), '')


def test_deploy_root_destination_owner_is_refused_before_source_read():
    with pytest.raises(DeployError, match='non-root'):
        deploy_certificate('/unused/cert', '/unused/key', '/unused/target',
                           expected_ip='203.0.113.10', trusted_source_root='/unused',
                           owner_uid=0, owner_gid=0)


def test_ipv6_and_named_staging_lineages_are_distinct():
    cfg = dataclasses.replace(config(), public_ip='2001:db8::10')
    setup_tls.build_setup_commands(cfg)
    named = dataclasses.replace(cfg, certificate_name='my-cert')
    assert dataclasses.replace(named, staging=True).effective_certificate_name != named.effective_certificate_name


def test_generated_hook_uses_fixed_arguments_and_ignores_other_lineages(tmp_path):
    helper = tmp_path / 'deploy_certificate.py'
    helper.write_text('import json,sys; print(json.dumps(sys.argv[1:]))')
    cfg = dataclasses.replace(config(), helper_install_dir=tmp_path,
                              python_executable=Path(sys.executable),
                              runtime_dir=tmp_path / "quote'$(whoami)")
    hook = tmp_path / 'hook'
    hook.write_bytes(setup_tls.build_deploy_wrapper(cfg))
    env = dict(os.environ, RENEWED_LINEAGE='/unrelated/certificate')
    ignored = subprocess.run(['/bin/sh', str(hook)], env=env, capture_output=True, text=True, check=True)
    assert ignored.stdout == ''
    env['RENEWED_LINEAGE'] = str(cfg.lineage_dir)
    result = subprocess.run(['/bin/sh', str(hook)], env=env, capture_output=True, text=True, check=True)
    arguments = json.loads(result.stdout)
    assert arguments[arguments.index('--destination-root') + 1] == str(cfg.runtime_dir)
    assert arguments[arguments.index('--source-certificate') + 1] == str(cfg.lineage_dir / 'fullchain.pem')
