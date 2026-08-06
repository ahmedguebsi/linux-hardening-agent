"""Service posture check behaviour (firewall, auditd, patching, time sync)."""

from __future__ import annotations

from hardening_agent.checks.services import (
    AuditdRunningCheck,
    FirewallEnabledCheck,
    PendingSecurityUpdatesCheck,
    TimeSyncCheck,
    UnattendedUpgradesCheck,
)
from hardening_agent.models import RemediationOutcome, Status
from tests.conftest import FakeSystem


class TestFirewall:
    def test_active_ufw_with_default_deny_passes(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.executables.add("ufw")
        fake_system.stub(
            ["ufw", "status", "verbose"],
            stdout=(
                "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
            ),
        )
        assert FirewallEnabledCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_inactive_ufw_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("ufw")
        fake_system.stub(["ufw", "status", "verbose"], stdout="Status: inactive\n")
        result = FirewallEnabledCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["active"] is False

    def test_active_but_allow_incoming_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("ufw")
        fake_system.stub(
            ["ufw", "status", "verbose"],
            stdout="Status: active\nDefault: allow (incoming), allow (outgoing)\n",
        )
        result = FirewallEnabledCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["default_deny_incoming"] is False

    def test_falls_back_to_nftables(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("nft")
        fake_system.stub(
            ["nft", "list", "ruleset"],
            stdout=(
                "table inet filter {\n"
                "  chain input {\n"
                "    type filter hook input priority 0; policy drop;\n"
                "  }\n"
                "}\n"
            ),
        )
        result = FirewallEnabledCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS
        assert result.evidence["backend"] == "nftables"

    def test_no_firewall_tooling_fails(self, fake_system: FakeSystem, make_context) -> None:
        assert FirewallEnabledCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_remediation_allows_ssh_before_enabling(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        """Ordering is the whole safety property: allow SSH, then deny by default."""
        fake_system.executables.add("ufw")
        for argv in (
            ["ufw", "allow", "OpenSSH"],
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            ["ufw", "--force", "enable"],
        ):
            fake_system.stub(argv)

        record = FirewallEnabledCheck().remediate(make_context(fake_system, allow_risky=True))

        assert record.outcome is RemediationOutcome.APPLIED
        executed = fake_system.executed
        assert executed.index(("ufw", "allow", "OpenSSH")) < executed.index(
            ("ufw", "default", "deny", "incoming")
        )
        assert executed.index(("ufw", "default", "deny", "incoming")) < executed.index(
            ("ufw", "--force", "enable")
        )

    def test_remediation_refused_without_allow_risky(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.executables.add("ufw")
        record = FirewallEnabledCheck().remediate(make_context(fake_system))
        assert record.outcome is RemediationOutcome.SKIPPED
        assert fake_system.executed == []

    def test_remediation_aborts_on_first_failure(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.executables.add("ufw")
        fake_system.stub(["ufw", "allow", "OpenSSH"], code=1, stderr="ERROR: bad rule")
        record = FirewallEnabledCheck().remediate(make_context(fake_system, allow_risky=True))
        assert record.outcome is RemediationOutcome.FAILED
        # The firewall must not be enabled if the SSH allow rule failed.
        assert ("ufw", "--force", "enable") not in fake_system.executed


class TestAuditd:
    def test_active_and_enabled_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("systemctl")
        fake_system.stub(["systemctl", "is-active", "auditd"], stdout="active\n")
        fake_system.stub(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")
        assert AuditdRunningCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_running_but_not_enabled_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("systemctl")
        fake_system.stub(["systemctl", "is-active", "auditd"], stdout="active\n")
        fake_system.stub(["systemctl", "is-enabled", "auditd"], stdout="disabled\n", code=1)
        result = AuditdRunningCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "not enabled at boot" in result.detail

    def test_skips_without_systemd(self, fake_system: FakeSystem, make_context) -> None:
        assert AuditdRunningCheck().audit(make_context(fake_system)).status is Status.SKIP


class TestUnattendedUpgrades:
    def test_enabled_config_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("apt-get")
        fake_system.files["/etc/apt/apt.conf.d/20auto-upgrades"] = (
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
        )
        assert UnattendedUpgradesCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_disabled_flag_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("apt-get")
        fake_system.files["/etc/apt/apt.conf.d/20auto-upgrades"] = (
            'APT::Periodic::Unattended-Upgrade "0";\n'
        )
        assert UnattendedUpgradesCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_commented_out_line_does_not_count_as_enabled(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.executables.add("apt-get")
        fake_system.files["/etc/apt/apt.conf.d/20auto-upgrades"] = (
            '// APT::Periodic::Unattended-Upgrade "1";\n'
        )
        assert UnattendedUpgradesCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_missing_config_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("apt-get")
        result = UnattendedUpgradesCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["config_present"] is False

    def test_skips_on_non_debian(self, fake_system: FakeSystem, make_context) -> None:
        assert UnattendedUpgradesCheck().audit(make_context(fake_system)).status is Status.SKIP


class TestPendingSecurityUpdates:
    def test_pending_security_update_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("apt-get")
        fake_system.stub(
            ["apt-get", "--just-print", "upgrade"],
            stdout=(
                "Inst openssl [3.0.2-0ubuntu1] (3.0.2-0ubuntu1.15 Ubuntu:24.04/noble-security)\n"
                "Inst vim [2:9.0] (2:9.1 Ubuntu:24.04/noble-updates)\n"
                "Conf openssl (3.0.2-0ubuntu1.15)\n"
            ),
        )
        result = PendingSecurityUpdatesCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["security_count"] == 1
        assert "openssl" in result.detail
        assert result.evidence["total_pending"] == 2

    def test_only_non_security_updates_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("apt-get")
        fake_system.stub(
            ["apt-get", "--just-print", "upgrade"],
            stdout="Inst vim [2:9.0] (2:9.1 Ubuntu:24.04/noble-updates)\n",
        )
        result = PendingSecurityUpdatesCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS
        assert result.evidence["total_pending"] == 1

    def test_is_not_remediable_by_design(self) -> None:
        """Installing updates restarts services; that is a change-window decision."""
        assert PendingSecurityUpdatesCheck.metadata.remediable is False


class TestTimeSync:
    def test_any_running_time_service_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("systemctl")
        fake_system.stub(
            ["systemctl", "is-active", "systemd-timesyncd"], stdout="inactive\n", code=1
        )
        fake_system.stub(["systemctl", "is-active", "chrony"], stdout="active\n")
        result = TimeSyncCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS
        assert result.evidence["running"] == ["chrony"]

    def test_no_time_sync_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.executables.add("systemctl")
        assert TimeSyncCheck().audit(make_context(fake_system)).status is Status.FAIL
