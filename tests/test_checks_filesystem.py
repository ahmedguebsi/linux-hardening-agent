"""Filesystem check behaviour."""

from __future__ import annotations

import pytest

from hardening_agent.checks.filesystem import (
    SeparateTmpPartitionCheck,
    ShadowPermissionsCheck,
    SudoersPermissionsCheck,
    TmpStickyBitCheck,
    WorldWritableFilesCheck,
)
from hardening_agent.models import RemediationOutcome, Status
from tests.conftest import FakeSystem


class TestFilePermissionSemantics:
    """max_mode is a ceiling, not an equality test."""

    @pytest.mark.parametrize("mode", [0o640, 0o600, 0o400, 0o000])
    def test_stricter_than_maximum_passes(
        self, fake_system: FakeSystem, make_context, mode: int
    ) -> None:
        fake_system.files["/etc/shadow"] = "root:x:1::::::\n"
        fake_system.modes["/etc/shadow"] = mode
        assert ShadowPermissionsCheck().audit(make_context(fake_system)).status is Status.PASS

    @pytest.mark.parametrize("mode", [0o644, 0o660, 0o777, 0o642])
    def test_looser_than_maximum_fails(
        self, fake_system: FakeSystem, make_context, mode: int
    ) -> None:
        fake_system.files["/etc/shadow"] = "root:x:1::::::\n"
        fake_system.modes["/etc/shadow"] = mode
        result = ShadowPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL

    def test_missing_required_file_fails(self, fake_system: FakeSystem, make_context) -> None:
        result = ShadowPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "missing" in result.detail

    def test_missing_optional_file_skips(self, fake_system: FakeSystem, make_context) -> None:
        """/etc/sudoers is required=False -- absence is not a finding."""
        result = SudoersPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.SKIP

    def test_remediation_only_clears_disallowed_bits(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.files["/etc/shadow"] = "x"
        fake_system.modes["/etc/shadow"] = 0o646
        ShadowPermissionsCheck().remediate(make_context(fake_system))
        # 0o646 & 0o640 == 0o640
        assert fake_system.modes["/etc/shadow"] == 0o640

    def test_remediation_dry_run_makes_no_change(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.files["/etc/shadow"] = "x"
        fake_system.modes["/etc/shadow"] = 0o777
        record = ShadowPermissionsCheck().remediate(make_context(fake_system, dry_run=True))
        assert record.outcome is RemediationOutcome.DRY_RUN
        assert fake_system.modes["/etc/shadow"] == 0o777
        assert fake_system.chmods == []


class TestStickyBit:
    def test_missing_sticky_bit_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.directories.add("/tmp")
        fake_system.modes["/tmp"] = 0o777
        result = TmpStickyBitCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "/tmp" in result.detail

    def test_sticky_bit_present_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.directories.add("/tmp")
        fake_system.modes["/tmp"] = 0o1777
        assert TmpStickyBitCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_remediation_preserves_existing_permissions(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.directories.add("/tmp")
        fake_system.modes["/tmp"] = 0o777
        TmpStickyBitCheck().remediate(make_context(fake_system))
        assert fake_system.modes["/tmp"] == 0o1777

    def test_skips_when_no_temp_dirs_exist(self, fake_system: FakeSystem, make_context) -> None:
        assert TmpStickyBitCheck().audit(make_context(fake_system)).status is Status.SKIP


class TestSeparateTmpPartition:
    def test_not_a_mount_point_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/proc/mounts"] = "/dev/sda1 / ext4 rw,relatime 0 0\n"
        result = SeparateTmpPartitionCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["mounted"] is False

    def test_mounted_with_all_options_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/proc/mounts"] = (
            "/dev/sda1 / ext4 rw,relatime 0 0\n"
            "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        )
        assert SeparateTmpPartitionCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_mounted_without_noexec_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/proc/mounts"] = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
        result = SeparateTmpPartitionCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["missing_options"] == ["noexec"]

    def test_is_not_remediable_by_design(self) -> None:
        """Editing fstab automatically can render a host unbootable."""
        assert SeparateTmpPartitionCheck.metadata.remediable is False


class TestWorldWritableFiles:
    def test_world_writable_file_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = "x"
        fake_system.modes["/etc/passwd"] = 0o644
        fake_system.files["/etc/evil.conf"] = "x"
        fake_system.modes["/etc/evil.conf"] = 0o666
        result = WorldWritableFilesCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "/etc/evil.conf" in result.detail

    def test_clean_etc_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = "x"
        fake_system.modes["/etc/passwd"] = 0o644
        assert WorldWritableFilesCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_directories_are_not_flagged(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = "x"
        fake_system.directories.add("/etc/ssl")
        fake_system.modes["/etc/ssl"] = 0o777
        assert WorldWritableFilesCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_skips_when_etc_is_empty(self, fake_system: FakeSystem, make_context) -> None:
        assert WorldWritableFilesCheck().audit(make_context(fake_system)).status is Status.SKIP
