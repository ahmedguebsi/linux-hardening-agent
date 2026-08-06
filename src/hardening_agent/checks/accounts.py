"""User account and authentication policy controls.

These parse ``/etc/passwd``, ``/etc/shadow`` and ``/etc/login.defs`` directly
rather than shelling out to ``getent``, because the files are the authoritative
local source and parsing them is both faster and testable without a host.
"""

from __future__ import annotations

import re

from ..models import CheckMetadata, Finding, RemediationOutcome, RemediationRecord, Severity
from .base import Check, CheckContext

ACCOUNT_TAGS = frozenset({"accounts", "authentication"})

LOGIN_DEFS = "/etc/login.defs"
# Shells that mean "this account cannot log in interactively".
NOLOGIN_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"})


def _parse_passwd(content: str) -> list[dict[str, str]]:
    """Parse /etc/passwd into records. Malformed lines are ignored, not fatal."""
    records = []
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        records.append(
            {
                "name": fields[0],
                "password": fields[1],
                "uid": fields[2],
                "gid": fields[3],
                "gecos": fields[4],
                "home": fields[5],
                "shell": fields[6],
            }
        )
    return records


def _parse_shadow(content: str) -> list[dict[str, str]]:
    records = []
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        records.append({"name": fields[0], "password": fields[1]})
    return records


def _login_defs_value(content: str, key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s+(\S+)", re.MULTILINE)
    match = pattern.search(content)
    return match.group(1) if match else None


class RootIsOnlyUidZeroCheck(Check):
    metadata = CheckMetadata(
        check_id="accounts_single_uid_zero",
        title="root is the only account with UID 0",
        description="No account other than root may have UID 0.",
        severity=Severity.CRITICAL,
        rationale=(
            "A second UID 0 account is full root access under a name that does "
            "not look like root, which is a classic persistence mechanism that "
            "survives password rotation and is easy to overlook in an audit."
        ),
        tags=ACCOUNT_TAGS | {"cis", "privilege-escalation", "persistence"},
        # Deleting or renumbering an account automatically is far too dangerous.
        remediable=False,
        references=("CIS Ubuntu 24.04 6.2.9",),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        content = ctx.system.read_text("/etc/passwd")
        if content is None:
            return Finding.errored("/etc/passwd is unreadable")
        uid_zero = [r["name"] for r in _parse_passwd(content) if r["uid"] == "0"]
        if uid_zero == ["root"]:
            return Finding.passed("root is the only UID 0 account", accounts=uid_zero)
        if not uid_zero:
            return Finding.failed("no UID 0 account exists at all", accounts=uid_zero)
        extra = [name for name in uid_zero if name != "root"]
        return Finding.failed(
            f"additional UID 0 account(s): {', '.join(extra)}",
            accounts=uid_zero,
            unexpected=extra,
        )


class EmptyPasswordCheck(Check):
    metadata = CheckMetadata(
        check_id="accounts_no_empty_passwords",
        title="No account has an empty password",
        description="Every /etc/shadow entry must have a password hash or be locked.",
        severity=Severity.CRITICAL,
        rationale=(
            "An empty password field means the account authenticates with no "
            "credential at all. Combined with any local or remote login path it "
            "is unauthenticated access."
        ),
        tags=ACCOUNT_TAGS | {"cis", "credentials"},
        remediable=True,
        risky_remediation=True,
        references=("CIS Ubuntu 24.04 6.2.1",),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        content = ctx.system.read_text("/etc/shadow")
        if content is None:
            return Finding.skipped("/etc/shadow is unreadable (requires root)")
        empty = [r["name"] for r in _parse_shadow(content) if r["password"] == ""]
        if empty:
            return Finding.failed(
                f"account(s) with empty password: {', '.join(empty)}", accounts=empty
            )
        return Finding.passed("no accounts with empty passwords")

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        """Lock the affected accounts with ``passwd -l``.

        Locking rather than setting a password: the agent has no safe way to
        choose or communicate a new credential, and a locked account is the
        secure default state.
        """
        content = ctx.system.read_text("/etc/shadow")
        if content is None:
            return RemediationRecord(RemediationOutcome.SKIPPED, "/etc/shadow is unreadable")
        empty = [r["name"] for r in _parse_shadow(content) if r["password"] == ""]
        if not empty:
            return RemediationRecord(RemediationOutcome.SKIPPED, "nothing to lock")
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN, f"would lock account(s): {', '.join(empty)}"
            )
        if not ctx.allow_risky:
            return RemediationRecord(
                RemediationOutcome.SKIPPED,
                "locking accounts is a risky remediation; re-run with --allow-risky",
            )
        commands: list[str] = []
        locked: list[str] = []
        for name in empty:
            result = ctx.system.run(["passwd", "-l", name])
            commands.append(result.display)
            if result.ok:
                locked.append(name)
        if not locked:
            return RemediationRecord(
                RemediationOutcome.FAILED,
                "passwd -l failed for all accounts",
                commands=tuple(commands),
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"locked account(s): {', '.join(locked)}",
            commands=tuple(commands),
        )


class PasswordMaxDaysCheck(Check):
    metadata = CheckMetadata(
        check_id="accounts_password_max_days",
        title="Password expiry policy is configured",
        description="PASS_MAX_DAYS in /etc/login.defs must be 365 or fewer.",
        severity=Severity.LOW,
        rationale=(
            "Bounded credential lifetime limits how long a leaked password stays "
            "useful. Kept at LOW severity because modern guidance (NIST 800-63B) "
            "favours breach-triggered rotation over forced expiry."
        ),
        tags=ACCOUNT_TAGS | {"cis", "policy"},
        remediable=True,
        references=("CIS Ubuntu 24.04 6.2.2", "NIST 800-63B 5.1.1.2"),
    )

    MAX_ALLOWED = 365

    def audit(self, ctx: CheckContext) -> Finding:
        content = ctx.system.read_text(LOGIN_DEFS)
        if content is None:
            return Finding.skipped(f"{LOGIN_DEFS} not found")
        raw = _login_defs_value(content, "PASS_MAX_DAYS")
        if raw is None:
            return Finding.failed("PASS_MAX_DAYS is not configured", configured=None)
        try:
            value = int(raw)
        except ValueError:
            return Finding.errored(f"PASS_MAX_DAYS is not an integer: {raw!r}", configured=raw)
        evidence = {"configured": value, "max_allowed": self.MAX_ALLOWED}
        if 0 < value <= self.MAX_ALLOWED:
            return Finding.passed(f"PASS_MAX_DAYS = {value}", **evidence)
        return Finding.failed(f"PASS_MAX_DAYS = {value}, expected 1-{self.MAX_ALLOWED}", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        content = ctx.system.read_text(LOGIN_DEFS)
        if content is None:
            return RemediationRecord(RemediationOutcome.SKIPPED, f"{LOGIN_DEFS} not found")
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would set PASS_MAX_DAYS to {self.MAX_ALLOWED} in {LOGIN_DEFS}",
                changed_paths=(LOGIN_DEFS,),
            )
        ctx.backup.backup_file(LOGIN_DEFS)
        pattern = re.compile(r"^\s*PASS_MAX_DAYS\s+.*$", re.MULTILINE)
        replacement = f"PASS_MAX_DAYS\t{self.MAX_ALLOWED}"
        updated = (
            pattern.sub(replacement, content)
            if pattern.search(content)
            else f"{content.rstrip()}\n{replacement}\n"
        )
        ctx.system.write_text(LOGIN_DEFS, updated, mode=0o644)
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"PASS_MAX_DAYS set to {self.MAX_ALLOWED}",
            changed_paths=(LOGIN_DEFS,),
            backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
        )


class SystemAccountShellCheck(Check):
    metadata = CheckMetadata(
        check_id="accounts_system_accounts_nologin",
        title="System accounts cannot log in interactively",
        description="Non-root accounts below UID_MIN must use a nologin shell.",
        severity=Severity.MEDIUM,
        rationale=(
            "Service accounts such as www-data or postgres should never have an "
            "interactive shell. If a service is compromised, a valid shell turns "
            "code execution into a comfortable foothold with a working login."
        ),
        tags=ACCOUNT_TAGS | {"cis", "service-accounts"},
        remediable=False,
        references=("CIS Ubuntu 24.04 6.2.11",),
    )

    # Accounts always exempt: root needs a shell, sync legitimately runs /bin/sync.
    EXEMPT = frozenset({"root", "sync", "shutdown", "halt"})

    def audit(self, ctx: CheckContext) -> Finding:
        passwd = ctx.system.read_text("/etc/passwd")
        if passwd is None:
            return Finding.errored("/etc/passwd is unreadable")
        defs = ctx.system.read_text(LOGIN_DEFS) or ""
        try:
            uid_min = int(_login_defs_value(defs, "UID_MIN") or 1000)
        except ValueError:
            uid_min = 1000

        offenders: list[dict[str, str]] = []
        for record in _parse_passwd(passwd):
            if record["name"] in self.EXEMPT:
                continue
            try:
                uid = int(record["uid"])
            except ValueError:
                continue
            if uid >= uid_min:
                continue
            if record["shell"] not in NOLOGIN_SHELLS:
                offenders.append(
                    {"name": record["name"], "uid": record["uid"], "shell": record["shell"]}
                )

        evidence = {"uid_min": uid_min, "offenders": offenders}
        if offenders:
            names = ", ".join(f"{o['name']}({o['shell']})" for o in offenders)
            return Finding.failed(
                f"{len(offenders)} system account(s) with a login shell: {names}", **evidence
            )
        return Finding.passed("all system accounts use a nologin shell", **evidence)


class RootPathIntegrityCheck(Check):
    metadata = CheckMetadata(
        check_id="accounts_root_home_permissions",
        title="root's home directory is not accessible to other users",
        description="/root must be mode 0700 or stricter.",
        severity=Severity.MEDIUM,
        rationale=(
            "/root commonly holds SSH keys, cloud credentials, shell history and "
            "backup archives. Any non-root read is a credential harvest."
        ),
        tags=ACCOUNT_TAGS | {"cis", "permissions"},
        remediable=True,
        references=("CIS Ubuntu 24.04 6.2.7",),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        info = ctx.system.stat("/root")
        if info is None:
            return Finding.skipped("/root does not exist")
        bits = info.permission_bits
        evidence = {"path": "/root", "mode": f"{bits:04o}", "uid": info.uid}
        if bits & 0o077:
            return Finding.failed(
                f"/root is mode {bits:04o}, expected 0700 or stricter", **evidence
            )
        return Finding.passed(f"/root is mode {bits:04o}", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN, "would chmod 0700 /root", changed_paths=("/root",)
            )
        try:
            ctx.system.chmod("/root", 0o700)
        except OSError as exc:
            return RemediationRecord(RemediationOutcome.FAILED, f"chmod failed: {exc}")
        return RemediationRecord(
            RemediationOutcome.APPLIED, "/root set to mode 0700", changed_paths=("/root",)
        )


CHECKS = (
    RootIsOnlyUidZeroCheck,
    EmptyPasswordCheck,
    PasswordMaxDaysCheck,
    SystemAccountShellCheck,
    RootPathIntegrityCheck,
)
