"""Profile-scoped local listener ownership. No capabilities or values on disk."""
import fcntl
import os
from pathlib import Path
import stat


class LeaderError(Exception):
    def __init__(self):
        super().__init__('ingress leader unavailable')


class LeaderLock:
    def __init__(self, home: Path):
        self.home = Path(home)
        self.fd = None

    def acquire(self):
        if self.fd is not None:
            return
        parent = lock = None
        try:
            if not self.home.is_absolute() or '..' in self.home.parts:
                raise LeaderError()
            parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
            for part in self.home.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            if os.fstat(parent).st_uid != os.getuid():
                raise LeaderError()
            try:
                os.mkdir('secrets-ingress', 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open('secrets-ingress', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            st = os.fstat(parent)
            if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise LeaderError()
            lock = os.open('leader.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
            st = os.fstat(lock)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                    or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
                raise LeaderError()
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = lock
            lock = None
        except (OSError, ValueError):
            raise LeaderError() from None
        finally:
            if lock is not None:
                os.close(lock)
            if parent is not None:
                os.close(parent)

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)
