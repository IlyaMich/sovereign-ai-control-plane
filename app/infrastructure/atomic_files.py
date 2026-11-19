"""Cross-process, same-filesystem publication primitives for operator/audit files.

The caller must use an on-disk filesystem supporting atomic hard links and
rename. We deliberately fail rather than fall back to a partially visible copy.
"""

from __future__ import annotations

import errno
import math
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from typing import Iterator, Protocol, cast


class _PosixFlock(Protocol):
    """POSIX lock interface, independent of the host type-checker's stubs."""

    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, fd: int, operation: int) -> None: ...


def fsync_directory(path: Path) -> None:
    """Sync published directory entries where the platform supports it."""
    if os.name == "nt":
        # Windows does not offer a portable Python fsync of directory handles.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
                raise
    finally:
        os.close(fd)


def publish_new_bytes(path: Path | str, data: bytes, *, mode: int = 0o600) -> None:
    """Fully write/sync a temporary file, then publish without replacing any file.

    FileExistsError means some other writer has published the destination. The
    caller MUST validate that winner's contents, not overwrite or delete it.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic, non-replacing publication. Unlike O_EXCL + write, no reader
        # can observe a partial destination. Link failure is fail-closed.
        os.link(temp_name, destination)
        fsync_directory(destination.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def read_regular_bytes(path: Path | str) -> bytes:
    """Reject symlinks and missing/nonregular published key material."""
    dest = Path(path)
    if dest.is_symlink() or not dest.is_file():
        raise ValueError("Expected a regular non-symlink file")
    return dest.read_bytes()


@contextmanager
def interprocess_lock(path: Path | str, *, timeout_seconds: float = 15.0) -> Iterator[None]:
    """Hold a cross-process exclusive file lock; no unlink-based stale lock files.

    Advisory: all release-activation writers must cooperate. OS closes/unlocks
    automatically after process death. Uses flock on POSIX, CRT locking on NT.
    """
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (float, int))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("Lock timeout must be finite and positive")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError("Lock file cannot be a symlink")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Lock target must be a regular file")
        deadline = time.monotonic() + float(timeout_seconds)
        if os.name == "nt":
            import msvcrt

            # CRT byte-range locking is most portable on a one-byte file.
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\x00")
                os.fsync(fd)

            def acquire() -> None:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

            def release() -> None:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

        else:
            # Direct fcntl attributes are absent from Windows mypy stubs.
            # Import only on POSIX, with an explicit typed contract.
            posix_locks = cast(_PosixFlock, import_module("fcntl"))

            def acquire() -> None:
                posix_locks.flock(fd, posix_locks.LOCK_EX | posix_locks.LOCK_NB)

            def release() -> None:
                posix_locks.flock(fd, posix_locks.LOCK_UN)

        while True:
            try:
                acquire()
                locked = True
                break
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES) and getattr(
                    exc, "winerror", None
                ) not in (33, 36):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out acquiring activation lock") from exc
                time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))
        yield
    finally:
        try:
            if locked:
                release()
        finally:
            os.close(fd)


def fsync_tree(root: Path) -> None:
    """Sync each staged policy file before its directory is made active."""
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Policy staging contains a symlink")
        if path.is_file():
            # Windows os.fsync uses CRT _commit, which requires a writable handle.
            # These are staged copies owned by the activator, not archived sources.
            with path.open("r+b") as stream:
                os.fsync(stream.fileno())
    for directory in sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True):
        fsync_directory(directory)
    fsync_directory(root)
