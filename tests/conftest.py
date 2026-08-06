"""Shared test fixtures.

The centrepiece is :class:`FakeSystem`, an in-memory implementation of
:class:`~hardening_agent.system.SystemInterface`. Because every check reaches the
host through that one interface, the entire check suite is testable on any
platform, without root, without a VM, and without mutating the machine running
the tests.

That is the concrete payoff of the dependency-inversion seam in
``system.py``: these tests would otherwise require a disposable Ubuntu box.
"""

from __future__ import annotations

import fnmatch
import stat as stat_module
from collections.abc import Sequence

import pytest

from hardening_agent.backup import BackupManager
from hardening_agent.checks.base import CheckContext
from hardening_agent.config import Config
from hardening_agent.models import HostInfo
from hardening_agent.system import CommandResult, FileStat, FilesystemStats


class FakeSystem:
    """In-memory host. Implements the full SystemInterface protocol."""

    def __init__(
        self,
        files: dict[str, str] | None = None,
        *,
        modes: dict[str, int] | None = None,
        owners: dict[str, tuple[int, int]] | None = None,
        directories: Sequence[str] = (),
        commands: dict[tuple[str, ...], CommandResult] | None = None,
        executables: Sequence[str] = (),
        filesystems: dict[str, FilesystemStats] | None = None,
        root: bool = True,
        host: HostInfo | None = None,
    ) -> None:
        self.filesystems: dict[str, FilesystemStats] = dict(filesystems or {})
        self.files: dict[str, str] = dict(files or {})
        self.modes: dict[str, int] = dict(modes or {})
        self.owners: dict[str, tuple[int, int]] = dict(owners or {})
        self.directories: set[str] = set(directories)
        self.commands: dict[tuple[str, ...], CommandResult] = dict(commands or {})
        self.executables: set[str] = set(executables)
        self._root = root
        self._host = host or HostInfo(
            hostname="test-host",
            os_name="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-41-generic",
            architecture="x86_64",
            virtualization="none",
        )
        # Recorded side effects, so tests can assert on what was written.
        self.writes: list[tuple[str, str, int | None]] = []
        self.chmods: list[tuple[str, int]] = []
        self.copies: list[tuple[str, str]] = []
        self.made_dirs: list[str] = []
        self.executed: list[tuple[str, ...]] = []

    # -- read surface -------------------------------------------------------
    def read_text(self, path: str) -> str | None:
        return self.files.get(path)

    def path_exists(self, path: str) -> bool:
        return path in self.files or path in self.directories

    def stat(self, path: str) -> FileStat | None:
        if not self.path_exists(path):
            return None
        is_dir = path in self.directories
        default_mode = 0o755 if is_dir else 0o644
        permission_bits = self.modes.get(path, default_mode)
        type_bits = stat_module.S_IFDIR if is_dir else stat_module.S_IFREG
        uid, gid = self.owners.get(path, (0, 0))
        return FileStat(
            mode=type_bits | permission_bits,
            uid=uid,
            gid=gid,
            size=len(self.files.get(path, "")),
            is_dir=is_dir,
            is_symlink=False,
        )

    def glob(self, pattern: str) -> tuple[str, ...]:
        if not pattern.startswith("/"):
            raise ValueError(f"glob pattern must be absolute, got {pattern!r}")
        candidates = sorted(set(self.files) | self.directories)
        return tuple(p for p in candidates if fnmatch.fnmatchcase(p, pattern))

    def filesystem_stats(self, path: str) -> FilesystemStats | None:
        return self.filesystems.get(path)

    def run(self, argv: Sequence[str], *, timeout: float = 15.0) -> CommandResult:
        args = tuple(str(a) for a in argv)
        self.executed.append(args)
        if args in self.commands:
            return self.commands[args]
        # Unstubbed commands behave like "not installed" rather than raising, so
        # a check that probes for an optional tool degrades to SKIP naturally.
        return CommandResult(args, 127, "", f"command not found: {args[0]}")

    def which(self, name: str) -> str | None:
        return f"/usr/sbin/{name}" if name in self.executables else None

    def is_root(self) -> bool:
        return self._root

    def host_info(self) -> HostInfo:
        return self._host

    # -- mutating surface ---------------------------------------------------
    def write_text(self, path: str, content: str, *, mode: int | None = None) -> None:
        self.files[path] = content
        if mode is not None:
            self.modes[path] = mode
        self.writes.append((path, content, mode))

    def chmod(self, path: str, mode: int) -> None:
        if not self.path_exists(path):
            raise OSError(f"no such file: {path}")
        self.modes[path] = mode
        self.chmods.append((path, mode))

    def copy_file(self, source: str, destination: str) -> None:
        if source not in self.files:
            raise OSError(f"no such file: {source}")
        self.files[destination] = self.files[source]
        self.modes[destination] = self.modes.get(source, 0o644)
        self.copies.append((source, destination))

    def makedirs(self, path: str, *, mode: int = 0o755) -> None:
        self.directories.add(path)
        self.modes[path] = mode
        self.made_dirs.append(path)

    # -- test helpers -------------------------------------------------------
    def stub(
        self, argv: Sequence[str], *, stdout: str = "", stderr: str = "", code: int = 0
    ) -> None:
        args = tuple(argv)
        self.commands[args] = CommandResult(args, code, stdout, stderr)

    def sysctl(self, key: str, value: str) -> None:
        """Convenience: populate the /proc/sys path for a sysctl key."""
        self.files["/proc/sys/" + key.replace(".", "/")] = f"{value}\n"


@pytest.fixture
def fake_system() -> FakeSystem:
    return FakeSystem()


@pytest.fixture
def config() -> Config:
    return Config().validate()


@pytest.fixture
def context(fake_system: FakeSystem) -> CheckContext:
    """A default context: root, not a dry run, risky remediations disallowed."""
    return CheckContext(
        system=fake_system,
        backup=BackupManager(fake_system, "/var/backups/hardening-agent"),
        dry_run=False,
        allow_risky=False,
    )


@pytest.fixture
def make_context():
    """Factory for contexts with non-default flags."""

    def _make(
        system: FakeSystem, *, dry_run: bool = False, allow_risky: bool = False
    ) -> CheckContext:
        return CheckContext(
            system=system,
            backup=BackupManager(system, "/var/backups/hardening-agent"),
            dry_run=dry_run,
            allow_risky=allow_risky,
        )

    return _make


@pytest.fixture
def hardened_system() -> FakeSystem:
    """A host that passes every sysctl and file-permission control.

    Used as the baseline for "does a compliant host report clean" tests; each
    test then breaks exactly one thing.
    """
    system = FakeSystem(
        files={
            "/etc/ssh/sshd_config": (
                "PermitRootLogin no\n"
                "PasswordAuthentication no\n"
                "PermitEmptyPasswords no\n"
                "X11Forwarding no\n"
                "MaxAuthTries 4\n"
                "ClientAliveInterval 300\n"
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
            ),
            "/etc/shadow": "root:$6$hash:19000:0:99999:7:::\nalice:$6$hash:19000:0:99999:7:::\n",
            "/etc/group": "root:x:0:\n",
            "/etc/gshadow": "root:*::\n",
            "/etc/login.defs": "PASS_MAX_DAYS\t365\nUID_MIN\t1000\n",
            "/proc/mounts": (
                "/dev/sda1 / ext4 rw,relatime 0 0\n"
                "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            ),
        },
        modes={
            "/etc/ssh/sshd_config": 0o600,
            "/etc/passwd": 0o644,
            "/etc/shadow": 0o640,
            "/etc/group": 0o644,
            "/etc/gshadow": 0o640,
            "/tmp": 0o1777,
            "/var/tmp": 0o1777,
            "/dev/shm": 0o1777,
            "/root": 0o700,
        },
        directories={"/tmp", "/var/tmp", "/dev/shm", "/root", "/etc", "/etc/ssh"},
    )
    for key, value in {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.tcp_syncookies": "1",
        "kernel.randomize_va_space": "2",
        "kernel.kptr_restrict": "1",
        "kernel.dmesg_restrict": "1",
        "kernel.unprivileged_bpf_disabled": "2",
        "fs.suid_dumpable": "0",
        "fs.protected_hardlinks": "1",
        "fs.protected_symlinks": "1",
    }.items():
        system.sysctl(key, value)
    return system
