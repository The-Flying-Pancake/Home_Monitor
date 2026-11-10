"""Link-safe file work for the root helpers (sitectl.py, updatectl.py, compat.py). Standard library only.

Root writes into folders the app's own account can change (the data folder, the key folder). A name
there may be a link the app account put in place, pointing at a file root must never touch. So:

  read_regular(path, limit)   reads a file only when it is a plain file, never through a link
  atomic_write(folder, name, data, mode, owner)
                              a new file with a random name, created with O_EXCL and O_NOFOLLOW inside
                              a folder opened without following links, owner and mode set on the open
                              file, then renamed into place (a link at the name is replaced, never followed)
  atomic_copy(folder, name, src, mode, owner)
                              the same, with the bytes of a file root made (read in pieces)
  open_dir(path)              a folder descriptor, refused when the path is a link
  unlink_in(folder, name)     removes a name inside a folder opened without following links
  service_ids()               the uid and gid of the monitor's account when running as root, else None

On Windows (the test suite) the link flags do not exist: plain calls are used instead.
"""

import os
import stat
from typing import Optional, Tuple

SERVICE_USER = "homelab-monitor"
POSIX = os.name == "posix"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_BINARY = getattr(os, "O_BINARY", 0)


class UnsafeFile(OSError):
    """The path is a link, not a plain file, or larger than allowed."""


def read_regular(path: str, limit: int) -> bytes:
    """The file's bytes, at most limit. Refused when the path is a link or not a plain file."""
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _BINARY)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeFile(f"{path} is not a plain file")
        if st.st_size > limit:
            raise UnsafeFile(f"{path} is larger than expected")
        chunks, left = [], limit + 1
        while left > 0:
            chunk = os.read(fd, min(left, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise UnsafeFile(f"{path} is larger than expected")
        return data
    finally:
        os.close(fd)


def open_dir(path: str) -> int:
    """A descriptor for the folder itself; a link at path is refused (POSIX only)."""
    if not POSIX:
        raise NotImplementedError("folder descriptors need a POSIX system")
    return os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)


def _is_link_or_missing_dir(path: str) -> None:
    if os.path.islink(path):
        raise UnsafeFile(f"{path} is a link")


def atomic_write(folder: str, name: str, data: bytes, mode: int = 0o600, owner: Optional[Tuple[int, int]] = None) -> str:
    """Puts data at folder/name through a new randomly named file; returns the full path.

    The folder is opened without following a link, the new file is created with O_EXCL and
    O_NOFOLLOW, its owner and mode are set on the open descriptor, and it is renamed over name
    in the same folder. A link at name is replaced, never written through."""
    return _atomic(folder, name, [data], mode, owner)


def atomic_copy(folder: str, name: str, src: str, mode: int = 0o600, owner: Optional[Tuple[int, int]] = None) -> str:
    """atomic_write with the bytes of src (a file in root's own private folder), read in pieces."""
    def pieces():
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                yield chunk
    return _atomic(folder, name, pieces(), mode, owner)


def _atomic(folder: str, name: str, chunks, mode: int, owner: Optional[Tuple[int, int]]) -> str:
    if "/" in name or "\\" in name or name in ("", ".", ".."):
        raise ValueError("a plain file name is expected")
    tmp = f".{name}.{os.urandom(6).hex()}.new"
    if POSIX:
        dfd = open_dir(folder)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, mode, dir_fd=dfd)
            try:
                try:
                    if owner is not None:
                        os.fchown(fd, owner[0], owner[1])
                    os.fchmod(fd, mode)
                    for data in chunks:
                        view = memoryview(data)
                        while view:
                            view = view[os.write(fd, view):]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
                raise
        finally:
            os.close(dfd)
        return os.path.join(folder, name)
    _is_link_or_missing_dir(folder)
    path = os.path.join(folder, tmp)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            for data in chunks:
                f.write(data)
        os.replace(path, os.path.join(folder, name))
    except BaseException:
        if os.path.exists(path):
            os.remove(path)
        raise
    return os.path.join(folder, name)


def unlink_in(folder: str, name: str) -> None:
    """Removes folder/name without following a link at the folder (the name itself is never followed)."""
    if POSIX:
        dfd = open_dir(folder)
        try:
            os.unlink(name, dir_fd=dfd)
        finally:
            os.close(dfd)
        return
    _is_link_or_missing_dir(folder)
    os.remove(os.path.join(folder, name))


def listdir(folder: str) -> list:
    """The names in a folder opened without following a link."""
    if POSIX:
        dfd = open_dir(folder)
        try:
            return os.listdir(dfd)
        finally:
            os.close(dfd)
    _is_link_or_missing_dir(folder)
    return os.listdir(folder)


def is_root() -> bool:
    return POSIX and hasattr(os, "geteuid") and os.geteuid() == 0


def service_ids(user: str = SERVICE_USER) -> Optional[Tuple[int, int]]:
    """(uid, gid) of the monitor's account when running as root; None when not root (nothing to drop).
    Raises KeyError when root and the account does not exist, so callers fail closed."""
    if not is_root():
        return None
    import pwd
    entry = pwd.getpwnam(user)
    return entry.pw_uid, entry.pw_gid
