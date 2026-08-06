"""SSH check behaviour, including the sshd_config parser's ordering semantics."""

from __future__ import annotations

import pytest

from hardening_agent.checks.base import load_sshd_directives
from hardening_agent.checks.ssh import (
    SSHConfigPermissionsCheck,
    SSHEmptyPasswordsCheck,
    SSHHostKeyPermissionsCheck,
    SSHMaxAuthTriesCheck,
    SSHPasswordAuthCheck,
    SSHRootLoginCheck,
)
from hardening_agent.models import RemediationOutcome, Status
from tests.conftest import FakeSystem


class TestSSHDConfigParser:
    def test_first_occurrence_wins(self, fake_system: FakeSystem) -> None:
        """OpenSSH honours the FIRST value for a keyword, not the last."""
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\nPermitRootLogin yes\n"
        directives = load_sshd_directives(fake_system)
        assert directives is not None
        assert directives["permitrootlogin"] == "no"

    def test_comments_and_blank_lines_ignored(self, fake_system: FakeSystem) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = (
            "# PermitRootLogin yes\n\n   \nPermitRootLogin no\n"
        )
        directives = load_sshd_directives(fake_system)
        assert directives == {"permitrootlogin": "no"}

    def test_keywords_are_case_insensitive(self, fake_system: FakeSystem) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "permitROOTlogin NO\n"
        directives = load_sshd_directives(fake_system)
        assert directives is not None
        assert directives["permitrootlogin"] == "NO"

    def test_include_is_expanded(self, fake_system: FakeSystem) -> None:
        """Ubuntu's stock layout: the drop-in is included before the main body."""
        fake_system.files["/etc/ssh/sshd_config"] = (
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
        )
        fake_system.files["/etc/ssh/sshd_config.d/50-cloud.conf"] = "PermitRootLogin no\n"
        directives = load_sshd_directives(fake_system)
        assert directives is not None
        # The include appears first, so its value wins -- this is the behaviour
        # that makes the check correct on a stock Ubuntu cloud image.
        assert directives["permitrootlogin"] == "no"

    def test_include_relative_path_resolves_under_etc_ssh(self, fake_system: FakeSystem) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "Include sshd_config.d/*.conf\n"
        fake_system.files["/etc/ssh/sshd_config.d/10-x.conf"] = "MaxAuthTries 2\n"
        directives = load_sshd_directives(fake_system)
        assert directives is not None
        assert directives["maxauthtries"] == "2"

    def test_match_block_contents_are_ignored(self, fake_system: FakeSystem) -> None:
        """Options inside Match are conditional and must not be read as global."""
        fake_system.files["/etc/ssh/sshd_config"] = (
            "PermitRootLogin no\nMatch User deploy\n    PermitRootLogin yes\n"
        )
        directives = load_sshd_directives(fake_system)
        assert directives is not None
        assert directives["permitrootlogin"] == "no"

    def test_missing_config_returns_none(self, fake_system: FakeSystem) -> None:
        assert load_sshd_directives(fake_system) is None


class TestSSHRootLogin:
    @pytest.mark.parametrize("value", ["no", "prohibit-password", "NO", "Prohibit-Password"])
    def test_accepted_values_pass(self, fake_system: FakeSystem, make_context, value: str) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = f"PermitRootLogin {value}\n"
        result = SSHRootLoginCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS

    @pytest.mark.parametrize("value", ["yes", "forced-commands-only"])
    def test_permissive_values_fail(
        self, fake_system: FakeSystem, make_context, value: str
    ) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = f"PermitRootLogin {value}\n"
        result = SSHRootLoginCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert value in result.detail

    def test_unset_uses_openssh_default(self, fake_system: FakeSystem, make_context) -> None:
        """Modern OpenSSH defaults to prohibit-password, which is acceptable."""
        fake_system.files["/etc/ssh/sshd_config"] = "# nothing relevant\n"
        result = SSHRootLoginCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS
        assert result.evidence["configured"] is None
        assert result.evidence["effective"] == "prohibit-password"

    def test_skips_when_sshd_absent(self, fake_system: FakeSystem, make_context) -> None:
        result = SSHRootLoginCheck().audit(make_context(fake_system))
        assert result.status is Status.SKIP


class TestSSHPasswordAuth:
    def test_unset_fails_because_default_is_yes(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\n"
        result = SSHPasswordAuthCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["effective"] == "yes"

    def test_is_flagged_risky(self) -> None:
        """Disabling password auth without a working key locks operators out."""
        assert SSHPasswordAuthCheck.metadata.risky_remediation is True


class TestSSHEmptyPasswords:
    def test_unset_passes_on_safe_default(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\n"
        result = SSHEmptyPasswordsCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS


class TestSSHMaxAuthTries:
    @pytest.mark.parametrize(
        "value,expected",
        [("1", Status.PASS), ("4", Status.PASS), ("5", Status.FAIL), ("6", Status.FAIL)],
    )
    def test_threshold(self, fake_system: FakeSystem, make_context, value, expected) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = f"MaxAuthTries {value}\n"
        assert SSHMaxAuthTriesCheck().audit(make_context(fake_system)).status is expected


class TestSSHRemediation:
    def test_dry_run_changes_nothing(self, fake_system: FakeSystem, make_context) -> None:
        original = "PermitRootLogin yes\n"
        fake_system.files["/etc/ssh/sshd_config"] = original
        ctx = make_context(fake_system, dry_run=True)

        record = SSHRootLoginCheck().remediate(ctx)

        assert record.outcome is RemediationOutcome.DRY_RUN
        assert fake_system.files["/etc/ssh/sshd_config"] == original
        assert fake_system.writes == []

    def test_applies_and_validates_with_sshd_t(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin yes\n"
        fake_system.stub(["sshd", "-t"])
        fake_system.stub(["systemctl", "reload", "ssh"])
        ctx = make_context(fake_system)

        record = SSHRootLoginCheck().remediate(ctx)

        assert record.outcome is RemediationOutcome.APPLIED
        content = fake_system.files["/etc/ssh/sshd_config"]
        assert "PermitRootLogin no" in content
        # The old line is commented, not deleted, so the change is reviewable.
        assert "# hardening-agent: was 'PermitRootLogin yes'" in content
        assert ("sshd", "-t") in fake_system.executed

    def test_rolls_back_when_sshd_t_rejects_the_config(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        """The single most important safety property in the codebase."""
        original = "PermitRootLogin yes\n"
        fake_system.files["/etc/ssh/sshd_config"] = original
        fake_system.stub(["sshd", "-t"], code=1, stderr="line 3: Bad configuration option")
        ctx = make_context(fake_system)

        record = SSHRootLoginCheck().remediate(ctx)

        assert record.outcome is RemediationOutcome.ROLLED_BACK
        assert fake_system.files["/etc/ssh/sshd_config"] == original
        assert record.backup_id is not None
        # sshd must never be reloaded with a config that failed validation.
        assert ("systemctl", "reload", "ssh") not in fake_system.executed

    def test_backs_up_before_writing(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin yes\n"
        fake_system.stub(["sshd", "-t"])
        fake_system.stub(["systemctl", "reload", "ssh"])

        SSHRootLoginCheck().remediate(make_context(fake_system))

        assert any(src == "/etc/ssh/sshd_config" for src, _ in fake_system.copies)

    def test_failed_reload_keeps_valid_config(self, fake_system: FakeSystem, make_context) -> None:
        """A valid file with a failed reload is applied, not rolled back."""
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin yes\n"
        fake_system.stub(["sshd", "-t"])
        fake_system.stub(["systemctl", "reload", "ssh"], code=1, stderr="unit not found")

        record = SSHRootLoginCheck().remediate(make_context(fake_system))

        assert record.outcome is RemediationOutcome.APPLIED
        assert "reload failed" in record.detail
        assert "PermitRootLogin no" in fake_system.files["/etc/ssh/sshd_config"]


class TestSSHConfigPermissions:
    def test_group_readable_config_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\n"
        fake_system.modes["/etc/ssh/sshd_config"] = 0o644
        result = SSHConfigPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "more permissive" in result.detail

    def test_non_root_owner_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\n"
        fake_system.modes["/etc/ssh/sshd_config"] = 0o600
        fake_system.owners["/etc/ssh/sshd_config"] = (1000, 1000)
        result = SSHConfigPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "owner uid 1000" in result.detail

    def test_remediation_preserves_only_allowed_bits(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.files["/etc/ssh/sshd_config"] = "x\n"
        fake_system.modes["/etc/ssh/sshd_config"] = 0o646
        SSHConfigPermissionsCheck().remediate(make_context(fake_system))
        assert fake_system.modes["/etc/ssh/sshd_config"] == 0o600


class TestSSHHostKeyPermissions:
    def test_world_readable_private_key_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/ssh_host_ed25519_key"] = "PRIVATE"
        fake_system.modes["/etc/ssh/ssh_host_ed25519_key"] = 0o644
        result = SSHHostKeyPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "ssh_host_ed25519_key" in result.detail

    def test_protected_keys_pass(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/ssh/ssh_host_ed25519_key"] = "PRIVATE"
        fake_system.modes["/etc/ssh/ssh_host_ed25519_key"] = 0o600
        fake_system.files["/etc/ssh/ssh_host_rsa_key"] = "PRIVATE"
        fake_system.modes["/etc/ssh/ssh_host_rsa_key"] = 0o640
        result = SSHHostKeyPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS

    def test_public_keys_are_not_inspected(self, fake_system: FakeSystem, make_context) -> None:
        """*.pub is meant to be world-readable; only *_key files matter."""
        fake_system.files["/etc/ssh/ssh_host_ed25519_key"] = "PRIVATE"
        fake_system.modes["/etc/ssh/ssh_host_ed25519_key"] = 0o600
        fake_system.files["/etc/ssh/ssh_host_ed25519_key.pub"] = "PUBLIC"
        fake_system.modes["/etc/ssh/ssh_host_ed25519_key.pub"] = 0o644
        result = SSHHostKeyPermissionsCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS

    def test_skips_when_no_keys(self, fake_system: FakeSystem, make_context) -> None:
        assert SSHHostKeyPermissionsCheck().audit(make_context(fake_system)).status is Status.SKIP
