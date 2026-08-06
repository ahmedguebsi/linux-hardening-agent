"""The single seam between the agent and the operating system.

Every filesystem read, command execution, and privilege query goes through
:class:`SystemInterface`. That gives us three properties that matter for a
security agent:

1. **Testability.** The whole check suite runs against an in-memory fake, so CI
   validates real logic on any platform without root and without a VM.
2. **Auditability.** There is exactly one place where the agent shells out, so a
   reviewer can confirm in one file that we never use ``shell=True``.
3. **Safety.** Read-only and mutating operations are separate methods, and the
   mutating ones are only reachable from remediation code paths.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import stat as stat_module
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import HostInfo

logger = logging.getLogger(__name__)

DEFAULT_COMMAND_TIMEOUT = 15.0


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Outcome of a subprocess execution."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def display(self) -> str:
        return " ".join(self.argv)


@dataclass(frozen=True, slots=True)
class FilesystemStats:
    """Capacity of a mounted filesystem, in bytes."""

    total_bytes: int
    available_bytes: int
    used_bytes: int

    @property
    def used_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return round(self.used_bytes / self.total_bytes * 100.0, 2)


@dataclass(frozen=True, slots=True)
class FileStat:
    """Subset of ``os.stat`` that the checks actually use.

    Narrowing the surface keeps the fake implementation small and stops checks
    from depending on platform-specific stat fields.
    """

    mode: int
    uid: int
    gid: int
    size: int
    is_dir: bool
    is_symlink: bool

    @property
    def permission_bits(self) -> int:
        """Permission bits only (``0o777`` mask), without the file type bits."""
        return self.mode & 0o7777


@runtime_checkable
class SystemInterface(Protocol):
    """Read/execute surface required by checks."""

    def read_text(self, path: str) -> str | None:
        """Return file contents, or ``None`` when the path is absent/unreadable."""

    def path_exists(self, path: str) -> bool: ...

    def stat(self, path: str) -> FileStat | None: ...

    def glob(self, pattern: str) -> tuple[str, ...]: ...

    def filesystem_stats(self, path: str) -> FilesystemStats | None: ...

    def run(
        self, argv: Sequence[str], *, timeout: float = DEFAULT_COMMAND_TIMEOUT
    ) -> CommandResult: ...

    def which(self, name: str) -> str | None: ...

    def is_root(self) -> bool: ...

    def host_info(self) -> HostInfo: ...

    # -- mutating operations, only used by remediation ---------------------
    def write_text(self, path: str, content: str, *, mode: int | None = None) -> None: ...

    def chmod(self, path: str, mode: int) -> None: ...

    def copy_file(self, source: str, destination: str) -> None: ...

    def makedirs(self, path: str, *, mode: int = 0o755) -> None: ...


class LocalSystem:
    """Real implementation backed by the running host."""

    def __init__(self, *, root: str = "/") -> None:
        # ``root`` exists so the agent can be pointed at a mounted filesystem
        # (e.g. a container inspecting the host at /host). It is not a security
        # boundary -- it is a convenience for read-only inspection.
        self._root = root.rstrip("/") or "/"

    def _resolve(self, path: str) -> Path:
        if self._root == "/":
            return Path(path)
        return Path(self._root) / path.lstrip("/")

    def read_text(self, path: str) -> str | None:
        try:
            return self._resolve(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            logger.debug("unreadable path", extra={"path": path})
            return None

    def path_exists(self, path: str) -> bool:
        try:
            return self._resolve(path).exists()
        except OSError:
            return False

    def stat(self, path: str) -> FileStat | None:
        target = self._resolve(path)
        try:
            raw = target.lstat()
        except OSError:
            return None
        return FileStat(
            mode=raw.st_mode,
            uid=raw.st_uid,
            gid=raw.st_gid,
            size=raw.st_size,
            is_dir=stat_module.S_ISDIR(raw.st_mode),
            is_symlink=stat_module.S_ISLNK(raw.st_mode),
        )

    def glob(self, pattern: str) -> tuple[str, ...]:
        """Expand an absolute glob pattern.

        Relative patterns are refused: they would resolve against the current
        working directory, which whoever invoked the agent controls. Every
        caller in this codebase passes a POSIX absolute path; the extra
        ``is_absolute`` arm only exists so the test suite can glob a temporary
        directory on a non-POSIX development machine.
        """
        candidate = Path(pattern)
        if not pattern.startswith("/") and not candidate.is_absolute():
            raise ValueError(f"glob pattern must be absolute, got {pattern!r}")

        if self._root != "/":
            base = Path(self._root)
            relative = pattern.lstrip("/")
        else:
            # Split the pattern into its anchor ("/" on POSIX, "C:\\" on
            # Windows) and the part Path.glob can match against.
            anchor = candidate.anchor or "/"
            base = Path(anchor)
            relative = pattern[len(anchor) :] if candidate.anchor else pattern.lstrip("/")

        try:
            matches = sorted(str(p) for p in base.glob(relative))
        except (OSError, ValueError):
            return ()
        if self._root != "/":
            matches = [m[len(self._root) :] or "/" for m in matches]
        return tuple(matches)

    def filesystem_stats(self, path: str) -> FilesystemStats | None:
        """Capacity of the filesystem backing ``path``.

        Resolved through ``_root``, so a container inspecting the host at /host
        reports the host's disks rather than its own overlay filesystem.
        """
        statvfs = getattr(os, "statvfs", None)
        if statvfs is None:  # non-POSIX development machine
            return None
        try:
            stats = statvfs(str(self._resolve(path)))
        except OSError:
            return None
        total = stats.f_blocks * stats.f_frsize
        if total <= 0:
            return None
        return FilesystemStats(
            total_bytes=total,
            available_bytes=stats.f_bavail * stats.f_frsize,
            # f_bfree, not f_bavail: reserved root blocks are not "used".
            # This matches what `df` reports.
            used_bytes=(stats.f_blocks - stats.f_bfree) * stats.f_frsize,
        )

    def run(
        self, argv: Sequence[str], *, timeout: float = DEFAULT_COMMAND_TIMEOUT
    ) -> CommandResult:
        args = tuple(str(a) for a in argv)
        if not args:
            raise ValueError("argv must not be empty")
        logger.debug("executing command", extra={"argv": args})
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, never shell=True
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                # A hardening agent must not inherit an attacker-influenced PATH
                # or LD_PRELOAD from whatever invoked it.
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except FileNotFoundError:
            return CommandResult(args, 127, "", f"command not found: {args[0]}")
        except PermissionError as exc:
            return CommandResult(args, 126, "", str(exc))
        except subprocess.TimeoutExpired:
            logger.warning("command timed out", extra={"argv": args, "timeout": timeout})
            return CommandResult(args, 124, "", "timed out", timed_out=True)
        return CommandResult(
            args,
            completed.returncode,
            completed.stdout or "",
            completed.stderr or "",
        )

    def which(self, name: str) -> str | None:
        return shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")

    def is_root(self) -> bool:
        # ``geteuid`` is POSIX-only; on Windows dev machines we are never root,
        # which is the safe answer because remediation is then refused.
        geteuid = getattr(os, "geteuid", None)
        return geteuid() == 0 if geteuid is not None else False

    def host_info(self) -> HostInfo:
        os_release = _parse_os_release(self.read_text("/etc/os-release"))
        return HostInfo(
            hostname=platform.node() or "unknown",
            os_name=os_release.get("NAME", platform.system() or "unknown"),
            os_version=os_release.get("VERSION_ID", platform.release() or "unknown"),
            kernel=platform.release() or "unknown",
            architecture=platform.machine() or "unknown",
            virtualization=self._detect_virtualization(),
        )

    def _detect_virtualization(self) -> str:
        if self.path_exists("/.dockerenv"):
            return "docker"
        cgroup = self.read_text("/proc/1/cgroup") or ""
        if "docker" in cgroup or "containerd" in cgroup:
            return "container"
        product = (self.read_text("/sys/class/dmi/id/product_name") or "").strip().lower()
        for needle, name in (
            ("kvm", "kvm"),
            ("vmware", "vmware"),
            ("virtualbox", "virtualbox"),
            ("amazon ec2", "ec2"),
        ):
            if needle in product:
                return name
        return "none" if product else "unknown"

    # -- mutating operations ------------------------------------------------
    def write_text(self, path: str, content: str, *, mode: int | None = None) -> None:
        """Atomically replace a file's contents.

        Written to a temporary file in the same directory then renamed, so a
        crash mid-write can never leave a half-written ``sshd_config`` behind.
        """
        target = self._resolve(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.hardening-agent.tmp")
        tmp.write_text(content, encoding="utf-8")
        if mode is not None:
            os.chmod(tmp, mode)
        elif target.exists():
            os.chmod(tmp, target.stat().st_mode & 0o7777)
        os.replace(tmp, target)

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(self._resolve(path), mode)

    def copy_file(self, source: str, destination: str) -> None:
        dst = self._resolve(destination)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self._resolve(source), dst)

    def makedirs(self, path: str, *, mode: int = 0o755) -> None:
        target = self._resolve(path)
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, mode)


def _parse_os_release(content: str | None) -> dict[str, str]:
    """Parse ``/etc/os-release`` key=value pairs, stripping optional quotes."""
    values: dict[str, str] = {}
    if not content:
        return values
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values
