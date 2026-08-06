"""OpenSSH server controls.

SSH is the primary remote-access path on a Linux server, so these controls carry
the highest severities in the catalogue. Every check here is remediable, and
every remediation validates with ``sshd -t`` before reloading -- see
:class:`~hardening_agent.checks.base.SSHOptionCheck`.
"""

from __future__ import annotations

from ..models import (
    CheckMetadata,
    Finding,
    RemediationOutcome,
    RemediationRecord,
    Severity,
)
from .base import SSHD_CONFIG_PATH, CheckContext, FilePermissionCheck, SSHOptionCheck

SSH_TAGS = frozenset({"ssh", "remote-access", "network"})


class SSHRootLoginCheck(SSHOptionCheck):
    metadata = CheckMetadata(
        check_id="ssh_root_login_disabled",
        title="SSH direct root login is disabled",
        description="PermitRootLogin must be 'no' or 'prohibit-password'.",
        severity=Severity.CRITICAL,
        rationale=(
            "Direct root login removes per-user accountability and gives brute-force "
            "attackers a known-valid username. Administrators should log in as "
            "themselves and escalate with sudo, which leaves an audit trail."
        ),
        tags=SSH_TAGS | {"cis", "access-control"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.7", "NIST 800-53 AC-6"),
    )
    option = "PermitRootLogin"
    accepted = frozenset({"no", "prohibit-password"})
    desired = "no"
    # OpenSSH >= 7.0 defaults to prohibit-password, which is acceptable.
    implicit_default = "prohibit-password"


class SSHPasswordAuthCheck(SSHOptionCheck):
    metadata = CheckMetadata(
        check_id="ssh_password_auth_disabled",
        title="SSH password authentication is disabled",
        description="PasswordAuthentication must be 'no'; use public keys.",
        severity=Severity.HIGH,
        rationale=(
            "Password authentication is the single largest source of successful "
            "SSH compromise via credential stuffing and brute force. Key-based "
            "auth is not guessable and does not transmit a reusable secret."
        ),
        tags=SSH_TAGS | {"cis", "authentication"},
        remediable=True,
        # Turning this off without a working key locks you out.
        risky_remediation=True,
        references=("CIS Ubuntu 24.04 5.1.15",),
    )
    option = "PasswordAuthentication"
    accepted = frozenset({"no"})
    desired = "no"
    implicit_default = "yes"


class SSHEmptyPasswordsCheck(SSHOptionCheck):
    metadata = CheckMetadata(
        check_id="ssh_empty_passwords_disabled",
        title="SSH rejects accounts with empty passwords",
        description="PermitEmptyPasswords must be 'no'.",
        severity=Severity.CRITICAL,
        rationale=(
            "An account with an empty password combined with PermitEmptyPasswords "
            "yes grants unauthenticated remote shell access to anyone who knows "
            "the username."
        ),
        tags=SSH_TAGS | {"cis", "authentication"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.16",),
    )
    option = "PermitEmptyPasswords"
    accepted = frozenset({"no"})
    desired = "no"
    implicit_default = "no"


class SSHX11ForwardingCheck(SSHOptionCheck):
    metadata = CheckMetadata(
        check_id="ssh_x11_forwarding_disabled",
        title="SSH X11 forwarding is disabled",
        description="X11Forwarding must be 'no' on servers.",
        severity=Severity.MEDIUM,
        rationale=(
            "X11 forwarding exposes the client's X server to the remote host; a "
            "compromised server can capture keystrokes from the client session. "
            "Servers have no legitimate need for it."
        ),
        tags=SSH_TAGS | {"cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.10",),
    )
    option = "X11Forwarding"
    accepted = frozenset({"no"})
    desired = "no"
    implicit_default = "no"


class SSHMaxAuthTriesCheck(SSHOptionCheck):
    metadata = CheckMetadata(
        check_id="ssh_max_auth_tries",
        title="SSH limits authentication attempts per connection",
        description="MaxAuthTries must be 4 or fewer.",
        severity=Severity.MEDIUM,
        rationale=(
            "Each connection allowing many attempts multiplies brute-force "
            "throughput. A low limit forces attackers to pay TCP handshake cost "
            "per guess and makes the attempts far more visible in logs."
        ),
        tags=SSH_TAGS | {"cis", "brute-force"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.9",),
    )
    option = "MaxAuthTries"
    accepted = frozenset({"1", "2", "3", "4"})
    desired = "4"
    implicit_default = "6"


class SSHClientAliveCheck(SSHOptionCheck):
    metadata = CheckMetadata(
        check_id="ssh_client_alive_interval",
        title="SSH idle sessions time out",
        description="ClientAliveInterval must be set to 300 seconds or less (non-zero).",
        severity=Severity.LOW,
        rationale=(
            "Idle sessions left open on an unlocked workstation are a lateral "
            "movement opportunity and hold privileged shells open indefinitely."
        ),
        tags=SSH_TAGS | {"cis", "session"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.12",),
    )
    option = "ClientAliveInterval"
    accepted = frozenset(str(value) for value in range(1, 301))
    desired = "300"
    implicit_default = "0"


class SSHConfigPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="ssh_config_permissions",
        title="sshd_config is owned by root and not world-readable",
        description=f"{SSHD_CONFIG_PATH} must be mode 0600 or stricter, owned by root.",
        severity=Severity.HIGH,
        rationale=(
            "A writable sshd_config lets a local user grant themselves remote "
            "root access on the next daemon restart. A world-readable one leaks "
            "the host's authentication posture to any local account."
        ),
        tags=SSH_TAGS | {"cis", "permissions"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.1",),
    )
    target_path = SSHD_CONFIG_PATH
    max_mode = 0o600
    expected_uid = 0
    expected_gid = 0
    required = False


class SSHHostKeyPermissionsCheck(FilePermissionCheck):
    """Private host keys must never be readable by non-root users.

    Overrides ``audit`` because the target is a glob, not a single path: a host
    can have several host keys and all of them matter.
    """

    metadata = CheckMetadata(
        check_id="ssh_host_key_permissions",
        title="SSH private host keys are protected",
        description="Private host keys must be mode 0640 or stricter and owned by root.",
        severity=Severity.CRITICAL,
        rationale=(
            "A leaked private host key allows an attacker to impersonate this "
            "server and transparently machine-in-the-middle every SSH session, "
            "including the credentials and commands within it."
        ),
        tags=SSH_TAGS | {"cis", "permissions", "cryptography"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.1.2",),
    )
    target_path = "/etc/ssh"
    max_mode = 0o640
    expected_uid = 0

    def audit(self, ctx: CheckContext) -> Finding:
        keys = ctx.system.glob("/etc/ssh/ssh_host_*_key")
        if not keys:
            return Finding.skipped("no SSH host keys found", path="/etc/ssh")

        offenders: list[dict[str, object]] = []
        inspected: list[str] = []
        for key_path in keys:
            info = ctx.system.stat(key_path)
            if info is None:
                continue
            inspected.append(key_path)
            bits = info.permission_bits
            if bits & ~self.max_mode or info.uid != 0:
                offenders.append({"path": key_path, "mode": f"{bits:04o}", "uid": info.uid})

        if offenders:
            summary = ", ".join(f"{o['path']} ({o['mode']})" for o in offenders)
            return Finding.failed(
                f"over-permissive private host key(s): {summary}",
                offenders=offenders,
                inspected=inspected,
            )
        return Finding.passed(
            f"{len(inspected)} private host key(s) correctly protected", inspected=inspected
        )

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        keys = ctx.system.glob("/etc/ssh/ssh_host_*_key")
        changed: list[str] = []
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would chmod 0600 on {len(keys)} private host key(s)",
                changed_paths=tuple(keys),
            )
        for key_path in keys:
            info = ctx.system.stat(key_path)
            if info is None or not (info.permission_bits & ~self.max_mode):
                continue
            ctx.backup.backup_file(key_path)
            try:
                ctx.system.chmod(key_path, 0o600)
            except OSError as exc:
                return RemediationRecord(
                    RemediationOutcome.FAILED,
                    f"chmod failed on {key_path}: {exc}",
                    tuple(changed),
                )
            changed.append(key_path)
        if not changed:
            return RemediationRecord(RemediationOutcome.SKIPPED, "no host key needed changing")
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"tightened permissions on {len(changed)} host key(s)",
            changed_paths=tuple(changed),
            backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
        )


CHECKS = (
    SSHRootLoginCheck,
    SSHPasswordAuthCheck,
    SSHEmptyPasswordsCheck,
    SSHX11ForwardingCheck,
    SSHMaxAuthTriesCheck,
    SSHClientAliveCheck,
    SSHConfigPermissionsCheck,
    SSHHostKeyPermissionsCheck,
)
