"""Host service posture: firewall, auditing, patching, time sync.

These checks talk to system tooling (``ufw``, ``systemctl``, ``dpkg``) through
the system interface. Each one degrades to ``SKIP`` when the tool is absent
rather than reporting a failure -- a host using nftables directly is not
non-compliant just because ``ufw`` is not installed.
"""

from __future__ import annotations

from ..models import CheckMetadata, Finding, RemediationOutcome, RemediationRecord, Severity
from .base import Check, CheckContext

SERVICE_TAGS = frozenset({"services", "systemd"})


def _unit_is_active(ctx: CheckContext, unit: str) -> bool | None:
    """Return whether a systemd unit is active, or ``None`` if systemd is absent."""
    if ctx.system.which("systemctl") is None:
        return None
    result = ctx.system.run(["systemctl", "is-active", unit])
    # is-active exits non-zero for inactive units, which is not an error.
    return result.stdout.strip() == "active"


def _unit_is_enabled(ctx: CheckContext, unit: str) -> bool | None:
    if ctx.system.which("systemctl") is None:
        return None
    result = ctx.system.run(["systemctl", "is-enabled", unit])
    return result.stdout.strip() in ("enabled", "enabled-runtime", "static")


class FirewallEnabledCheck(Check):
    metadata = CheckMetadata(
        check_id="services_firewall_enabled",
        title="A host firewall is active with a default-deny inbound policy",
        description="ufw or nftables must be active and default-deny for incoming traffic.",
        severity=Severity.HIGH,
        rationale=(
            "Security groups protect the north-south edge, but a host firewall is "
            "what limits east-west movement once an attacker is already inside "
            "the VPC. Default-deny means a service accidentally bound to 0.0.0.0 "
            "is not automatically reachable."
        ),
        tags=SERVICE_TAGS | {"network", "firewall", "cis"},
        remediable=True,
        # Enabling a default-deny firewall over SSH can end the session.
        risky_remediation=True,
        references=("CIS Ubuntu 24.04 4.1.1",),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        if ctx.system.which("ufw") is not None:
            return self._audit_ufw(ctx)
        if ctx.system.which("nft") is not None:
            return self._audit_nftables(ctx)
        return Finding.failed(
            "neither ufw nor nft is installed; no host firewall is manageable",
            ufw=False,
            nftables=False,
        )

    def _audit_ufw(self, ctx: CheckContext) -> Finding:
        result = ctx.system.run(["ufw", "status", "verbose"])
        if not result.ok:
            return Finding.errored(
                f"`ufw status` failed: {result.stderr.strip() or result.returncode}",
                command=result.display,
            )
        output = result.stdout
        active = "Status: active" in output
        # ufw prints e.g. "Default: deny (incoming), allow (outgoing), ..."
        default_deny = "deny (incoming)" in output or "reject (incoming)" in output
        evidence = {"backend": "ufw", "active": active, "default_deny_incoming": default_deny}
        if active and default_deny:
            return Finding.passed("ufw is active with default-deny incoming", **evidence)
        if not active:
            return Finding.failed("ufw is installed but not active", **evidence)
        return Finding.failed("ufw is active but does not default-deny incoming", **evidence)

    def _audit_nftables(self, ctx: CheckContext) -> Finding:
        result = ctx.system.run(["nft", "list", "ruleset"])
        if not result.ok:
            return Finding.errored(
                f"`nft list ruleset` failed: {result.stderr.strip()}", command=result.display
            )
        ruleset = result.stdout
        has_input_chain = "hook input" in ruleset
        default_drop = "policy drop" in ruleset
        evidence = {
            "backend": "nftables",
            "input_chain": has_input_chain,
            "policy_drop": default_drop,
        }
        if has_input_chain and default_drop:
            return Finding.passed("nftables input chain has policy drop", **evidence)
        return Finding.failed("nftables ruleset has no input chain with a drop policy", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        """Enable ufw with default-deny, preserving SSH access first.

        The SSH allow rule is added *before* enabling the firewall. Getting this
        order wrong disconnects every remote administrator on the host, so it is
        also gated behind ``--allow-risky``.
        """
        if ctx.system.which("ufw") is None:
            return RemediationRecord(
                RemediationOutcome.UNSUPPORTED, "ufw is not installed; configure nftables manually"
            )
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                "would run: ufw allow OpenSSH; ufw default deny incoming; ufw --force enable",
            )
        if not ctx.allow_risky:
            return RemediationRecord(
                RemediationOutcome.SKIPPED,
                "enabling a default-deny firewall can sever remote access; "
                "re-run with --allow-risky",
            )

        commands: list[str] = []
        # Allow SSH first, unconditionally, before any deny policy is applied.
        for argv in (
            ["ufw", "allow", "OpenSSH"],
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            ["ufw", "--force", "enable"],
        ):
            result = ctx.system.run(argv)
            commands.append(result.display)
            if not result.ok:
                return RemediationRecord(
                    RemediationOutcome.FAILED,
                    f"`{result.display}` failed: {result.stderr.strip()}",
                    commands=tuple(commands),
                )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            "ufw enabled with default-deny incoming and OpenSSH allowed",
            commands=tuple(commands),
        )


class AuditdRunningCheck(Check):
    metadata = CheckMetadata(
        check_id="services_auditd_running",
        title="The audit daemon is installed and running",
        description="auditd must be active so kernel audit events are recorded.",
        severity=Severity.MEDIUM,
        rationale=(
            "auditd is the only mechanism that records syscall-level activity "
            "such as privilege escalation and file access. Without it, incident "
            "response has no local evidence of what an attacker did."
        ),
        tags=SERVICE_TAGS | {"audit", "logging", "cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 4.1.1.1",),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        active = _unit_is_active(ctx, "auditd")
        if active is None:
            return Finding.skipped("systemd is not available on this host")
        enabled = _unit_is_enabled(ctx, "auditd")
        evidence = {"unit": "auditd", "active": active, "enabled": enabled}
        if active and enabled:
            return Finding.passed("auditd is active and enabled at boot", **evidence)
        if active and not enabled:
            return Finding.failed("auditd is running but not enabled at boot", **evidence)
        return Finding.failed("auditd is not running", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        if ctx.system.which("systemctl") is None:
            return RemediationRecord(RemediationOutcome.UNSUPPORTED, "systemd not available")
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN, "would run: systemctl enable --now auditd"
            )
        result = ctx.system.run(["systemctl", "enable", "--now", "auditd"])
        if not result.ok:
            return RemediationRecord(
                RemediationOutcome.FAILED,
                f"could not start auditd: {result.stderr.strip()}; "
                f"is the auditd package installed?",
                commands=(result.display,),
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED, "auditd enabled and started", commands=(result.display,)
        )


class UnattendedUpgradesCheck(Check):
    metadata = CheckMetadata(
        check_id="services_unattended_upgrades_enabled",
        title="Automatic security updates are enabled",
        description="unattended-upgrades must be installed and active.",
        severity=Severity.HIGH,
        rationale=(
            "The overwhelming majority of real-world compromises exploit a "
            "vulnerability with an available patch. Automated security patching "
            "closes the window between disclosure and remediation without "
            "depending on a human being on call."
        ),
        tags=SERVICE_TAGS | {"patching", "cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 1.9",),
    )

    CONFIG_PATH = "/etc/apt/apt.conf.d/20auto-upgrades"

    def audit(self, ctx: CheckContext) -> Finding:
        if ctx.system.which("apt-get") is None:
            return Finding.skipped("not a Debian/Ubuntu host")
        config = ctx.system.read_text(self.CONFIG_PATH)
        if config is None:
            return Finding.failed(
                f"{self.CONFIG_PATH} is missing; unattended upgrades are not configured",
                config_present=False,
            )
        # Look for: APT::Periodic::Unattended-Upgrade "1";
        enabled = any(
            "Unattended-Upgrade" in line and '"1"' in line
            for line in config.splitlines()
            if not line.strip().startswith("//")
        )
        active = _unit_is_active(ctx, "unattended-upgrades")
        evidence = {"config_present": True, "config_enabled": enabled, "unit_active": active}
        if enabled:
            return Finding.passed("unattended security upgrades are enabled", **evidence)
        return Finding.failed(
            "unattended-upgrades is configured but the periodic flag is not set to 1", **evidence
        )

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        if ctx.system.which("apt-get") is None:
            return RemediationRecord(RemediationOutcome.UNSUPPORTED, "not a Debian/Ubuntu host")
        content = (
            "// Managed by hardening-agent\n"
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
        )
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would write periodic upgrade flags to {self.CONFIG_PATH}",
                changed_paths=(self.CONFIG_PATH,),
            )
        ctx.backup.backup_file(self.CONFIG_PATH)
        ctx.system.write_text(self.CONFIG_PATH, content, mode=0o644)
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            "enabled periodic package list updates and unattended upgrades",
            changed_paths=(self.CONFIG_PATH,),
            backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
        )


class PendingSecurityUpdatesCheck(Check):
    metadata = CheckMetadata(
        check_id="services_no_pending_security_updates",
        title="No pending security updates",
        description="The host must have no uninstalled security updates.",
        severity=Severity.HIGH,
        rationale=(
            "A pending security update is a known, published vulnerability with "
            "a working patch that this host has not applied. It is the most "
            "directly actionable signal in the entire report."
        ),
        tags=SERVICE_TAGS | {"patching", "vulnerability"},
        # Applying updates can restart services; that is a change-window
        # decision, not something an audit agent should do unprompted.
        remediable=False,
        references=("CIS Ubuntu 24.04 1.9",),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        if ctx.system.which("apt-get") is None:
            return Finding.skipped("not a Debian/Ubuntu host")
        # --just-print against the security-only upgrade set. Read-only: this
        # simulates the upgrade and installs nothing.
        result = ctx.system.run(["apt-get", "--just-print", "upgrade"], timeout=60.0)
        if not result.ok:
            return Finding.errored(
                f"apt-get --just-print upgrade failed: {result.stderr.strip()}",
                command=result.display,
            )
        security_updates = [
            line.split()[1]
            for line in result.stdout.splitlines()
            if line.startswith("Inst ") and "security" in line.lower() and len(line.split()) > 1
        ]
        total = sum(1 for line in result.stdout.splitlines() if line.startswith("Inst "))
        evidence = {
            "security_updates": security_updates,
            "security_count": len(security_updates),
            "total_pending": total,
        }
        if security_updates:
            preview = ", ".join(security_updates[:10])
            return Finding.failed(
                f"{len(security_updates)} pending security update(s): {preview}", **evidence
            )
        return Finding.passed(
            f"no pending security updates ({total} non-security update(s) available)", **evidence
        )


class TimeSyncCheck(Check):
    metadata = CheckMetadata(
        check_id="services_time_sync_enabled",
        title="Time synchronisation is active",
        description="systemd-timesyncd, chrony or ntpd must be running.",
        severity=Severity.MEDIUM,
        rationale=(
            "Correlating logs across hosts during an incident requires accurate "
            "clocks. Clock drift also breaks TLS certificate validation and "
            "time-based authentication such as TOTP and AWS SigV4."
        ),
        tags=SERVICE_TAGS | {"time", "logging", "cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 2.3.1",),
    )

    CANDIDATE_UNITS = ("systemd-timesyncd", "chrony", "chronyd", "ntp", "ntpsec")

    def audit(self, ctx: CheckContext) -> Finding:
        if ctx.system.which("systemctl") is None:
            return Finding.skipped("systemd is not available on this host")
        running = [unit for unit in self.CANDIDATE_UNITS if _unit_is_active(ctx, unit)]
        evidence = {"candidates": list(self.CANDIDATE_UNITS), "running": running}
        if running:
            return Finding.passed(f"time synchronisation active via {running[0]}", **evidence)
        return Finding.failed("no time synchronisation service is running", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        if ctx.system.which("systemctl") is None:
            return RemediationRecord(RemediationOutcome.UNSUPPORTED, "systemd not available")
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN, "would run: systemctl enable --now systemd-timesyncd"
            )
        result = ctx.system.run(["systemctl", "enable", "--now", "systemd-timesyncd"])
        if not result.ok:
            return RemediationRecord(
                RemediationOutcome.FAILED,
                f"could not start systemd-timesyncd: {result.stderr.strip()}",
                commands=(result.display,),
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            "systemd-timesyncd enabled and started",
            commands=(result.display,),
        )


CHECKS = (
    FirewallEnabledCheck,
    AuditdRunningCheck,
    UnattendedUpgradesCheck,
    PendingSecurityUpdatesCheck,
    TimeSyncCheck,
)
