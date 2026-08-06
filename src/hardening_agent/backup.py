"""Backup and rollback for remediation.

Rule: the agent never modifies a file it has not first copied. Every remediation
run gets one backup set identified by a timestamp; if any step of a remediation
fails, the caller restores that set.

Layout::

    /var/backups/hardening-agent/
      20260806T101500Z-a1b2c3/
        manifest.json
        files/etc/ssh/sshd_config
        files/etc/sysctl.d/99-hardening.conf

The original absolute path is preserved under ``files/`` so a human can restore
by hand with ``cp`` if the agent itself is broken -- an important property for a
tool that can lock you out of a host.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .logging_setup import get_logger
from .system import SystemInterface

logger = get_logger("backup")

MANIFEST_NAME = "manifest.json"


class BackupError(RuntimeError):
    """Raised when a backup cannot be created or restored."""


@dataclass(slots=True)
class BackupSet:
    """A group of files backed up together, restorable as a unit."""

    backup_id: str
    root: str
    entries: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def manifest_path(self) -> str:
        return f"{self.root}/{MANIFEST_NAME}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at)),
            "entries": dict(self.entries),
        }


class BackupManager:
    """Creates and restores backup sets through the system interface."""

    def __init__(self, system: SystemInterface, base_dir: str, *, keep: int = 20) -> None:
        self._system = system
        self._base_dir = base_dir.rstrip("/")
        self._keep = keep
        self._current: BackupSet | None = None

    @property
    def current(self) -> BackupSet | None:
        return self._current

    def start_set(self) -> BackupSet:
        """Begin a new backup set. Reuses the active one if already started."""
        if self._current is not None:
            return self._current
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup_id = f"{stamp}-{secrets.token_hex(3)}"
        root = f"{self._base_dir}/{backup_id}"
        try:
            # 0o700: backups contain copies of /etc/shadow-adjacent files and
            # must never be world-readable.
            self._system.makedirs(root, mode=0o700)
        except OSError as exc:
            raise BackupError(f"cannot create backup directory {root}: {exc}") from exc
        self._current = BackupSet(backup_id=backup_id, root=root)
        logger.info("backup set opened", extra={"backup_id": backup_id, "root": root})
        return self._current

    def backup_file(self, path: str) -> str | None:
        """Copy ``path`` into the active set. Returns the backup location.

        A missing source is not an error: some remediations create a file that
        did not previously exist. The manifest records the absence so rollback
        knows the file should be removed rather than restored.
        """
        backup_set = self.start_set()
        if not self._system.path_exists(path):
            backup_set.entries[path] = ""
            logger.debug("source absent, recorded for rollback", extra={"path": path})
            self._write_manifest(backup_set)
            return None

        destination = f"{backup_set.root}/files{path}"
        try:
            self._system.copy_file(path, destination)
        except OSError as exc:
            raise BackupError(f"cannot back up {path}: {exc}") from exc
        backup_set.entries[path] = destination
        self._write_manifest(backup_set)
        logger.info("file backed up", extra={"path": path, "destination": destination})
        return destination

    def restore_set(self, backup_set: BackupSet | None = None) -> tuple[str, ...]:
        """Restore every file in the set to its original location."""
        target = backup_set or self._current
        if target is None:
            raise BackupError("no backup set to restore")
        restored: list[str] = []
        for original, stored in target.entries.items():
            try:
                if stored:
                    self._system.copy_file(stored, original)
                    restored.append(original)
                else:
                    # File did not exist before; best-effort truncate back to
                    # absent by writing nothing is wrong, so we leave a marker
                    # in the log and let the operator decide.
                    logger.warning(
                        "file did not exist before remediation; manual removal may be needed",
                        extra={"path": original, "backup_id": target.backup_id},
                    )
            except OSError as exc:
                logger.error(
                    "restore failed",
                    extra={"path": original, "backup_id": target.backup_id, "error": str(exc)},
                )
                raise BackupError(f"cannot restore {original}: {exc}") from exc
        logger.info(
            "backup set restored",
            extra={"backup_id": target.backup_id, "restored": restored},
        )
        return tuple(restored)

    def prune(self) -> tuple[str, ...]:
        """Delete all but the newest ``keep`` backup sets.

        Returns the ids that *should* be removed. Deletion is intentionally left
        to the caller/installer script: recursive removal as root is the single
        most dangerous operation this codebase could contain, so it is not
        implemented in the Python agent at all.
        """
        existing = sorted(self._system.glob(f"{self._base_dir}/*/{MANIFEST_NAME}"))
        ids = [entry.rsplit("/", 2)[-2] for entry in existing]
        if len(ids) <= self._keep:
            return ()
        stale = tuple(ids[: len(ids) - self._keep])
        logger.info("stale backup sets detected", extra={"stale": stale, "keep": self._keep})
        return stale

    def _write_manifest(self, backup_set: BackupSet) -> None:
        payload = json.dumps(backup_set.to_dict(), indent=2, sort_keys=True) + "\n"
        try:
            self._system.write_text(backup_set.manifest_path, payload, mode=0o600)
        except OSError as exc:
            raise BackupError(f"cannot write manifest: {exc}") from exc
