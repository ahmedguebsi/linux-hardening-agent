"""Backup and rollback behaviour."""

from __future__ import annotations

import json

import pytest

from hardening_agent.backup import MANIFEST_NAME, BackupManager
from tests.conftest import FakeSystem


@pytest.fixture
def manager(fake_system: FakeSystem) -> BackupManager:
    return BackupManager(fake_system, "/var/backups/hardening-agent", keep=3)


class TestBackupSets:
    def test_set_is_created_lazily(self, manager: BackupManager) -> None:
        assert manager.current is None
        manager.start_set()
        assert manager.current is not None

    def test_repeated_start_reuses_the_same_set(self, manager: BackupManager) -> None:
        """All files touched by one remediation run must roll back together."""
        first = manager.start_set()
        second = manager.start_set()
        assert first is second

    def test_directory_is_owner_only(self, manager: BackupManager, fake_system: FakeSystem) -> None:
        """Backups contain copies of /etc/shadow-adjacent files."""
        backup_set = manager.start_set()
        assert fake_system.modes[backup_set.root] == 0o700


class TestBackupFile:
    def test_content_is_copied(self, manager: BackupManager, fake_system: FakeSystem) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "original content"
        destination = manager.backup_file("/etc/ssh/sshd_config")
        assert destination is not None
        assert fake_system.files[destination] == "original content"

    def test_original_path_preserved_in_layout(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        """So an operator can restore by hand if the agent itself is broken."""
        fake_system.files["/etc/ssh/sshd_config"] = "x"
        destination = manager.backup_file("/etc/ssh/sshd_config")
        assert destination is not None
        assert destination.endswith("/files/etc/ssh/sshd_config")

    def test_absent_source_is_recorded_not_an_error(self, manager: BackupManager) -> None:
        """Some remediations create a file that did not exist before."""
        assert manager.backup_file("/etc/does-not-exist") is None
        assert manager.current is not None
        assert manager.current.entries["/etc/does-not-exist"] == ""

    def test_manifest_written_with_restrictive_mode(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        fake_system.files["/etc/passwd"] = "x"
        manager.backup_file("/etc/passwd")
        assert manager.current is not None
        manifest = fake_system.files[manager.current.manifest_path]
        assert fake_system.modes[manager.current.manifest_path] == 0o600
        payload = json.loads(manifest)
        assert "/etc/passwd" in payload["entries"]
        assert payload["backup_id"] == manager.current.backup_id

    def test_multiple_files_in_one_set(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        fake_system.files["/etc/a"] = "a"
        fake_system.files["/etc/b"] = "b"
        manager.backup_file("/etc/a")
        manager.backup_file("/etc/b")
        assert manager.current is not None
        assert set(manager.current.entries) == {"/etc/a", "/etc/b"}


class TestRestore:
    def test_restores_original_content(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "original"
        manager.backup_file("/etc/ssh/sshd_config")
        fake_system.files["/etc/ssh/sshd_config"] = "corrupted by remediation"

        manager.restore_set()

        assert fake_system.files["/etc/ssh/sshd_config"] == "original"

    def test_restores_every_file_in_the_set(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        fake_system.files["/etc/a"] = "a-original"
        fake_system.files["/etc/b"] = "b-original"
        manager.backup_file("/etc/a")
        manager.backup_file("/etc/b")
        fake_system.files["/etc/a"] = "broken"
        fake_system.files["/etc/b"] = "broken"

        restored = manager.restore_set()

        assert set(restored) == {"/etc/a", "/etc/b"}
        assert fake_system.files["/etc/a"] == "a-original"
        assert fake_system.files["/etc/b"] == "b-original"

    def test_restore_without_a_set_raises(self, manager: BackupManager) -> None:
        from hardening_agent.backup import BackupError

        with pytest.raises(BackupError, match="no backup set"):
            manager.restore_set()

    def test_previously_absent_file_is_not_restored(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        """Nothing to restore; the operator is warned instead of us guessing."""
        manager.backup_file("/etc/new-file")
        fake_system.files["/etc/new-file"] = "created by remediation"
        restored = manager.restore_set()
        assert restored == ()


class TestPrune:
    def test_nothing_stale_below_the_limit(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        for index in range(2):
            fake_system.files[f"/var/backups/hardening-agent/set-{index}/{MANIFEST_NAME}"] = "{}"
        assert manager.prune() == ()

    def test_oldest_sets_identified_beyond_the_limit(
        self, manager: BackupManager, fake_system: FakeSystem
    ) -> None:
        for index in range(5):
            fake_system.files[f"/var/backups/hardening-agent/set-{index}/{MANIFEST_NAME}"] = "{}"
        # keep=3, so the two oldest (lexicographically first) are stale.
        assert manager.prune() == ("set-0", "set-1")

    def test_prune_does_not_delete(self, manager: BackupManager, fake_system: FakeSystem) -> None:
        """Recursive removal as root is deliberately not implemented in Python."""
        for index in range(5):
            fake_system.files[f"/var/backups/hardening-agent/set-{index}/{MANIFEST_NAME}"] = "{}"
        manager.prune()
        assert f"/var/backups/hardening-agent/set-0/{MANIFEST_NAME}" in fake_system.files
