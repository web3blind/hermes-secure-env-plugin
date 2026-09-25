"""Filesystem identity and native page attachment fail-closed checks."""
import pytest

from secure_env_ingress.vault_ingress import bind_vault_home, assert_vault_home


def test_reject_home_and_vault_symlinks(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    alias = tmp_path / 'alias'
    alias.symlink_to(home, target_is_directory=True)
    monkeypatch.setenv('HERMES_HOME', str(alias))
    with pytest.raises(ValueError, match='symlink'):
        bind_vault_home(alias)
    monkeypatch.setenv('HERMES_HOME', str(home))
    (home / 'vault').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        bind_vault_home(home)


def test_reject_replaced_root_and_symlinked_vault_files(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    monkeypatch.setenv('HERMES_HOME', str(home))
    binding = bind_vault_home(home)
    home.rename(tmp_path / 'old-home')
    home.mkdir(mode=0o700)
    with pytest.raises(ValueError, match='vault path changed'):
        assert_vault_home(binding)
    vault = home / 'vault'
    vault.mkdir(mode=0o700)
    (vault / 'vault.key').symlink_to(tmp_path / 'target')
    with pytest.raises(ValueError, match='unsafe vault file'):
        bind_vault_home(home)


@pytest.mark.parametrize('component', ['home', 'vault', 'vault.key', 'vault.json.enc'])
def test_reject_unsafe_permissions(tmp_path, monkeypatch, component):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    vault = home / 'vault'
    vault.mkdir(mode=0o700)
    monkeypatch.setenv('HERMES_HOME', str(home))
    if component in ('home', 'vault'):
        path = home if component == 'home' else vault
        path.chmod(0o770)
    else:
        path = vault / component
        path.write_bytes(b'synthetic-only')
        path.chmod(0o644)
    with pytest.raises(ValueError, match='unsafe vault'):
        bind_vault_home(home)


def test_reject_replaced_parent(tmp_path, monkeypatch):
    parent = tmp_path / 'profile-parent'
    home = parent / 'home'
    home.mkdir(parents=True, mode=0o700)
    monkeypatch.setenv('HERMES_HOME', str(home))
    binding = bind_vault_home(home)
    parent.rename(tmp_path / 'former-parent')
    home.mkdir(parents=True, mode=0o700)
    with pytest.raises(ValueError, match='vault path changed'):
        assert_vault_home(binding)
