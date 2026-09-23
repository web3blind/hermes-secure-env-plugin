from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.deploy_certificate import DeployError, deploy_certificate
from scripts.external_probe import ProbeError, parse_probe_response, request_external_probe
from scripts.setup_tls import CONFIRMATION, SetupConfig, build_setup_commands, collect_preflight, run_setup
from test_tls import cert_material


def test_deploy_creates_atomic_generation_pointer_with_strict_modes(tmp_path):
    source = tmp_path / "letsencrypt"
    cert, key, root = cert_material(source / "live" / "127.0.0.1")
    destination = tmp_path / "runtime"
    result = deploy_certificate(
        cert,
        key,
        destination,
        expected_ip="127.0.0.1",
        trusted_source_root=source,
        trust_roots=root,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    current = destination / "current"
    assert current.is_symlink()
    assert current.resolve() == result.generation
    assert (current / "fullchain.pem").stat().st_mode & 0o777 == 0o644
    assert (current / "privkey.pem").stat().st_mode & 0o777 == 0o600
    assert result.generation.parent == destination / "generations"


def test_deploy_rejects_source_outside_trusted_root(tmp_path):
    cert, key, root = cert_material(tmp_path / "outside")
    with pytest.raises(DeployError):
        deploy_certificate(
            cert,
            key,
            tmp_path / "runtime",
            expected_ip="127.0.0.1",
            trusted_source_root=tmp_path / "trusted",
            trust_roots=root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )


def test_deploy_rejects_symlink_destination_component(tmp_path):
    source = tmp_path / "source"
    cert, key, root = cert_material(source)
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(DeployError):
        deploy_certificate(
            cert,
            key,
            linked / "tls",
            expected_ip="127.0.0.1",
            trusted_source_root=source,
            trust_roots=root,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )


def test_setup_defaults_to_plan_only_and_requires_exact_confirmation(tmp_path):
    config = SetupConfig(public_ip="203.0.113.4", runtime_dir=tmp_path / "tls", hermes_user="hermes")
    commands = build_setup_commands(config)
    assert commands
    assert all(isinstance(command, tuple) for command in commands)
    called = []
    report = run_setup(config, execute=lambda argv: called.append(tuple(argv)))
    assert report.applied is False
    assert called == []
    with pytest.raises(PermissionError):
        run_setup(config, apply=True, confirmation="yes", execute=lambda argv: None)
    run_setup(config, apply=True, confirmation=CONFIRMATION, execute=lambda argv: called.append(tuple(argv)))
    assert tuple(called) == commands
    assert all("shell" not in part for command in called for part in command)


def test_setup_uses_snap_certbot_without_guessing_or_enabling_timer(tmp_path):
    staging = build_setup_commands(
        SetupConfig(public_ip="203.0.113.4", runtime_dir=tmp_path / "tls", hermes_user="hermes")
    )
    assert any(command[0] == "/snap/bin/certbot" and "--staging" in command for command in staging)
    assert not any(command[:3] == ("systemctl", "enable", "--now") for command in staging)
    assert not any(command[:3] == ("/snap/bin/certbot", "renew", "--dry-run") for command in staging)

    production = build_setup_commands(
        SetupConfig(
            public_ip="203.0.113.4",
            runtime_dir=tmp_path / "tls",
            hermes_user="hermes",
            staging=False,
        )
    )
    assert any(command[:3] == ("/snap/bin/certbot", "renew", "--dry-run") for command in production)


@pytest.mark.parametrize("module", ["scripts.setup_tls", "scripts.deploy_certificate", "scripts.external_probe"])
def test_tls_script_modules_have_working_help(module):
    completed = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout


def test_setup_preflight_cli_is_read_only(tmp_path):
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.setup_tls",
            "--preflight",
            "--public-ip",
            "203.0.113.4",
            "--runtime-dir",
            str(tmp_path / "tls"),
            "--hermes-user",
            "hermes",
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["mode"] == "preflight"
    assert report["production_ready"] is False
    assert not (tmp_path / "tls").exists()


def test_preflight_collects_safe_metadata_without_external_success_claim(tmp_path):
    report = collect_preflight(
        public_ip="203.0.113.4",
        plugin_port=18443,
        runtime_dir=tmp_path / "missing",
        command_runner=lambda argv: (127, ""),
    )
    assert report["public_ip"] == "203.0.113.4"
    assert report["external_reachability"]["status"] == "not_checked"
    serialized = json.dumps(report)
    assert "private_key" not in serialized


def test_external_probe_requires_explicit_remote_vantage_and_target_echo():
    valid = {
        "vantage": {"kind": "external", "id": "probe-eu-1"},
        "target": {"host": "203.0.113.4", "port": 18443},
        "reachable": True,
        "observed_at": "2026-09-23T00:00:00Z",
    }
    result = parse_probe_response(valid, expected_host="203.0.113.4", expected_port=18443)
    assert result.reachable is True
    for change in (
        {"vantage": {"kind": "local", "id": "localhost"}},
        {"target": {"host": "203.0.113.5", "port": 18443}},
        {"vantage": {"kind": "external", "id": "203.0.113.4"}},
    ):
        payload = valid | change
        with pytest.raises(ProbeError):
            parse_probe_response(payload, expected_host="203.0.113.4", expected_port=18443)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@probe.example/check",
        "https://probe.example/check#fragment",
        "https://localhost/check",
    ],
)
def test_external_probe_rejects_unsafe_service_urls_before_fetch(url):
    called = False

    def fetch(_request, _timeout):
        nonlocal called
        called = True
        return b"{}"

    with pytest.raises(ProbeError):
        request_external_probe(url, target_host="203.0.113.4", target_port=18443, fetch=fetch)
    assert called is False
