"""Linux Landlock ABI>=3: SFTP can only write incoming; no shell/chroot/root daemon."""
import ctypes
import os
from pathlib import Path
import platform
import stat

class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]
class Beneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

def api():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("SUPPORTED_LINUX_ARCH_REQUIRED")
    libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, ctypes.c_void_p(), 0, 1)
    if abi < 3: raise ValueError("LANDLOCK_ABI3_REQUIRED_NO_FALLBACK")
    return libc, abi

def restrict(inbox, read_dirs=("/usr", "/lib", "/lib64", "/bin"), read_files=("/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/localtime", "/dev/null", "/dev/urandom")):
    libc, abi = api()
    handled = (1 << 15) - 1  # ABI3 rights EXECUTE through TRUNCATE, no version-dependent bits.
    attr = Ruleset(handled)
    fd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if fd < 0: raise OSError(ctypes.get_errno(), "LANDLOCK_CREATE")
    try:
        def add(path, rights, optional=False):
            try: target = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except FileNotFoundError:
                if optional: return
                raise
            try:
                # Directory flags must not be used for single-file rules.
                if not stat.S_ISDIR(os.fstat(target).st_mode): rights &= (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14)
                rule = Beneath(rights, target)
                if libc.syscall(445, fd, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), "LANDLOCK_RULE")
            finally: os.close(target)
        for path in read_dirs: add(path, (1 << 0) | (1 << 2) | (1 << 3), optional=True)
        for path in read_files: add(path, (1 << 2), optional=True)
        add(str(inbox), (1 << 1) | (1 << 2) | (1 << 3) | (1 << 8) | (1 << 14))
        if libc.prctl(38, 1, 0, 0, 0) != 0: raise OSError(ctypes.get_errno(), "NO_NEW_PRIVS")
        if libc.syscall(446, fd, 0) != 0: raise OSError(ctypes.get_errno(), "LANDLOCK_RESTRICT")
    finally: os.close(fd)
    return abi

if __name__ == "__main__":
    import sys
    # Native child probe, exact fixture directory supplied by native acceptance.
    root = Path(sys.argv[1]); inside = root / "inside"; outside = root / "outside"
    inside.mkdir(); outside.mkdir(); (outside / "public-fixture").write_bytes(b"fixture")
    restrict(inside)
    (inside / "allowed").write_bytes(b"fixture")
    try: (outside / "forbidden").write_bytes(b"must-not-write")
    except PermissionError: pass
    else: raise SystemExit("LANDLOCK_WRITE_ESCAPE")
    try: (outside / "public-fixture").read_bytes()
    except PermissionError: pass
    else: raise SystemExit("LANDLOCK_READ_ESCAPE")
    print("LANDLOCK_REAL_UID_READ_WRITE_DENIAL_PASS")
