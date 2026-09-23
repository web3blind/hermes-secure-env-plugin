import pytest
from secure_env_ingress.leader import LeaderLock, LeaderError


def test_exclusive_and_release(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    first = LeaderLock(home)
    second = LeaderLock(home)
    first.acquire()
    with pytest.raises(LeaderError):
        second.acquire()
    first.close()
    second.acquire()
    second.close()


def test_lock_refuses_symlink(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    (home / 'secrets-ingress').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(LeaderError):
        LeaderLock(home).acquire()


def test_lock_refuses_unsafe_permissions(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    directory = home / 'secrets-ingress'
    directory.mkdir(mode=0o755)
    with pytest.raises(LeaderError):
        LeaderLock(home).acquire()


def test_profile_locks_independent(tmp_path):
    a, b = tmp_path / 'a', tmp_path / 'b'
    a.mkdir(mode=0o700)
    b.mkdir(mode=0o700)
    la, lb = LeaderLock(a), LeaderLock(b)
    try:
        la.acquire()
        lb.acquire()
    finally:
        la.close()
        lb.close()
