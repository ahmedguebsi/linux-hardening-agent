"""Kernel/sysctl check behaviour."""

from __future__ import annotations

import pytest

from hardening_agent.checks.base import SYSCTL_CONF_PATH, _upsert_sysctl_line
from hardening_agent.checks.kernel import (
    ASLRCheck,
    IPForwardingCheck,
    KptrRestrictCheck,
    TCPSynCookiesCheck,
    UnprivilegedBPFCheck,
)
from hardening_agent.models import HostInfo, RemediationOutcome, Status
from tests.conftest import FakeSystem


class TestSysctlAudit:
    def test_matching_value_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.sysctl("kernel.randomize_va_space", "2")
        result = ASLRCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS
        assert result.evidence["actual"] == "2"

    def test_wrong_value_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.sysctl("kernel.randomize_va_space", "0")
        result = ASLRCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "expected 2" in result.detail

    def test_absent_key_skips_not_fails(self, fake_system: FakeSystem, make_context) -> None:
        """An unsupported kernel knob is not a misconfiguration."""
        result = ASLRCheck().audit(make_context(fake_system))
        assert result.status is Status.SKIP

    def test_whitespace_is_normalised(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/proc/sys/net/ipv4/tcp_syncookies"] = "  1  \n"
        assert TCPSynCookiesCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_reads_proc_not_config_file(self, fake_system: FakeSystem, make_context) -> None:
        """Ground truth is the running kernel, not what /etc claims."""
        fake_system.files["/etc/sysctl.conf"] = "kernel.randomize_va_space = 2\n"
        fake_system.sysctl("kernel.randomize_va_space", "0")
        assert ASLRCheck().audit(make_context(fake_system)).status is Status.FAIL


class TestMultiValueChecks:
    @pytest.mark.parametrize(
        "value,expected", [("0", Status.FAIL), ("1", Status.PASS), ("2", Status.PASS)]
    )
    def test_kptr_restrict_accepts_1_or_2(
        self, fake_system: FakeSystem, make_context, value, expected
    ) -> None:
        fake_system.sysctl("kernel.kptr_restrict", value)
        assert KptrRestrictCheck().audit(make_context(fake_system)).status is expected

    @pytest.mark.parametrize(
        "value,expected", [("0", Status.FAIL), ("1", Status.PASS), ("2", Status.PASS)]
    )
    def test_unprivileged_bpf_accepts_1_or_2(
        self, fake_system: FakeSystem, make_context, value, expected
    ) -> None:
        fake_system.sysctl("kernel.unprivileged_bpf_disabled", value)
        assert UnprivilegedBPFCheck().audit(make_context(fake_system)).status is expected


class TestIPForwardingContextAwareness:
    """ip_forward is required on container hosts; flagging it is a false positive."""

    def test_fails_on_a_plain_server(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.sysctl("net.ipv4.ip_forward", "1")
        assert IPForwardingCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_skips_inside_a_container(self, make_context) -> None:
        system = FakeSystem(
            host=HostInfo("c", "Ubuntu", "24.04", "6.8.0", "x86_64", virtualization="docker")
        )
        system.sysctl("net.ipv4.ip_forward", "1")
        result = IPForwardingCheck().audit(make_context(system))
        assert result.status is Status.SKIP

    def test_skips_when_docker_bridge_present(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.sysctl("net.ipv4.ip_forward", "1")
        fake_system.directories.add("/sys/class/net/docker0")
        result = IPForwardingCheck().audit(make_context(fake_system))
        assert result.status is Status.SKIP
        assert result.evidence["reason"] == "docker_detected"


class TestSysctlRemediation:
    def test_dry_run_writes_nothing(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.sysctl("kernel.randomize_va_space", "0")
        record = ASLRCheck().remediate(make_context(fake_system, dry_run=True))
        assert record.outcome is RemediationOutcome.DRY_RUN
        assert fake_system.writes == []
        assert fake_system.executed == []

    def test_persists_and_applies(self, fake_system: FakeSystem, make_context) -> None:
        """Both steps are needed: the file survives reboot, sysctl -w takes effect now."""
        fake_system.sysctl("kernel.randomize_va_space", "0")
        fake_system.stub(["sysctl", "-w", "kernel.randomize_va_space=2"])

        record = ASLRCheck().remediate(make_context(fake_system))

        assert record.outcome is RemediationOutcome.APPLIED
        assert "kernel.randomize_va_space = 2" in fake_system.files[SYSCTL_CONF_PATH]
        assert ("sysctl", "-w", "kernel.randomize_va_space=2") in fake_system.executed

    def test_rolls_back_when_sysctl_w_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.sysctl("kernel.randomize_va_space", "0")
        fake_system.files[SYSCTL_CONF_PATH] = "# existing\n"
        fake_system.stub(
            ["sysctl", "-w", "kernel.randomize_va_space=2"], code=1, stderr="permission denied"
        )

        record = ASLRCheck().remediate(make_context(fake_system))

        assert record.outcome is RemediationOutcome.ROLLED_BACK
        assert fake_system.files[SYSCTL_CONF_PATH] == "# existing\n"


class TestSysctlLineUpsert:
    def test_appends_when_absent(self) -> None:
        result = _upsert_sysctl_line("# header\n", "a.b", "1")
        assert result == "# header\na.b = 1\n"

    def test_replaces_existing_key(self) -> None:
        result = _upsert_sysctl_line("a.b = 0\nc.d = 9\n", "a.b", "1")
        assert result == "a.b = 1\nc.d = 9\n"
        assert result.count("a.b") == 1

    def test_tolerates_missing_trailing_newline(self) -> None:
        assert _upsert_sysctl_line("x.y = 1", "a.b", "2") == "x.y = 1\na.b = 2\n"

    def test_does_not_match_similar_key_prefix(self) -> None:
        """a.b must not be confused with a.b.c."""
        result = _upsert_sysctl_line("a.b.c = 0\n", "a.b", "1")
        assert "a.b.c = 0" in result
        assert "a.b = 1" in result
