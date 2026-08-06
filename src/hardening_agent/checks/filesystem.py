"""Filesystem permission and layout controls."""

from __future__ import annotations

from ..models import CheckMetadata, Finding, RemediationOutcome, RemediationRecord, Severity
from .base import Check, CheckContext, FilePermissionCheck

FS_TAGS = frozenset({"filesystem", "permissions"})


class PasswdPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="fs_passwd_permissions",
        title="/etc/passwd has correct permissions",
        description="/etc/passwd must be mode 0644 or stricter, owned by root:root.",
        severity=Severity.HIGH,
        rationale=(
            "/etc/passwd must stay world-readable for name resolution, but a "
            "writable /etc/passwd is instant privilege escalation: add a UID 0 "
            "entry and log in as it."
        ),
        tags=FS_TAGS | {"cis", "accounts"},
        remediable=True,
        references=("CIS Ubuntu 24.04 6.1.1",),
    )
    target_path = "/etc/passwd"
    max_mode = 0o644
    expected_uid = 0
    expected_gid = 0


class ShadowPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="fs_shadow_permissions",
        title="/etc/shadow is not readable by non-root users",
        description="/etc/shadow must be mode 0640 or stricter, owned by root.",
        severity=Severity.CRITICAL,
        rationale=(
            "/etc/shadow holds password hashes. Any local read gives an attacker "
            "an offline cracking target with no rate limit and no logging."
        ),
        tags=FS_TAGS | {"cis", "accounts", "credentials"},
        remediable=True,
        references=("CIS Ubuntu 24.04 6.1.2",),
    )
    target_path = "/etc/shadow"
    max_mode = 0o640
    expected_uid = 0


class GshadowPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="fs_gshadow_permissions",
        title="/etc/gshadow is not readable by non-root users",
        description="/etc/gshadow must be mode 0640 or stricter, owned by root.",
        severity=Severity.HIGH,
        rationale=(
            "/etc/gshadow contains group password hashes; exposure allows an "
            "attacker to join privileged groups such as sudo or docker."
        ),
        tags=FS_TAGS | {"cis", "accounts", "credentials"},
        remediable=True,
        references=("CIS Ubuntu 24.04 6.1.4",),
    )
    target_path = "/etc/gshadow"
    max_mode = 0o640
    expected_uid = 0
    required = False


class GroupPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="fs_group_permissions",
        title="/etc/group has correct permissions",
        description="/etc/group must be mode 0644 or stricter, owned by root:root.",
        severity=Severity.MEDIUM,
        rationale=(
            "A writable /etc/group lets a local user add themselves to sudo, "
            "docker, or disk and escalate to root."
        ),
        tags=FS_TAGS | {"cis", "accounts"},
        remediable=True,
        references=("CIS Ubuntu 24.04 6.1.3",),
    )
    target_path = "/etc/group"
    max_mode = 0o644
    expected_uid = 0
    expected_gid = 0


class CrontabPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="fs_crontab_permissions",
        title="/etc/crontab is restricted to root",
        description="/etc/crontab must be mode 0600 or stricter, owned by root:root.",
        severity=Severity.HIGH,
        rationale=(
            "Cron entries execute as root on a schedule. Write access to the "
            "crontab is equivalent to root, and read access reveals scheduled "
            "jobs that an attacker can target or predict."
        ),
        tags=FS_TAGS | {"cis", "cron"},
        remediable=True,
        references=("CIS Ubuntu 24.04 2.4.1.1",),
    )
    target_path = "/etc/crontab"
    max_mode = 0o600
    expected_uid = 0
    expected_gid = 0
    required = False


class SudoersPermissionsCheck(FilePermissionCheck):
    metadata = CheckMetadata(
        check_id="fs_sudoers_permissions",
        title="/etc/sudoers is restricted",
        description="/etc/sudoers must be mode 0440 or stricter, owned by root:root.",
        severity=Severity.CRITICAL,
        rationale=(
            "Write access to /etc/sudoers is a direct, silent path to root for any local account."
        ),
        tags=FS_TAGS | {"cis", "privilege-escalation"},
        remediable=True,
        references=("CIS Ubuntu 24.04 5.3.1",),
    )
    target_path = "/etc/sudoers"
    max_mode = 0o440
    expected_uid = 0
    expected_gid = 0
    required = False


class TmpStickyBitCheck(Check):
    metadata = CheckMetadata(
        check_id="fs_tmp_sticky_bit",
        title="World-writable directories have the sticky bit set",
        description="/tmp, /var/tmp and /dev/shm must have the sticky bit (mode 1777).",
        severity=Severity.HIGH,
        rationale=(
            "Without the sticky bit, any user can delete or replace another "
            "user's files in a shared directory. That enables file-substitution "
            "attacks against processes that read from /tmp."
        ),
        tags=FS_TAGS | {"cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 1.1.2.1",),
    )

    STICKY = 0o1000
    DIRECTORIES = ("/tmp", "/var/tmp", "/dev/shm")

    def audit(self, ctx: CheckContext) -> Finding:
        offenders: list[dict[str, object]] = []
        inspected: list[str] = []
        for directory in self.DIRECTORIES:
            info = ctx.system.stat(directory)
            if info is None:
                continue
            inspected.append(directory)
            if not info.permission_bits & self.STICKY:
                offenders.append({"path": directory, "mode": f"{info.permission_bits:04o}"})
        if not inspected:
            return Finding.skipped("none of the shared temp directories exist")
        if offenders:
            names = ", ".join(str(o["path"]) for o in offenders)
            return Finding.failed(
                f"sticky bit missing on: {names}", offenders=offenders, inspected=inspected
            )
        return Finding.passed(
            f"sticky bit set on {len(inspected)} shared director(ies)", inspected=inspected
        )

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        changed: list[str] = []
        for directory in self.DIRECTORIES:
            info = ctx.system.stat(directory)
            if info is None or info.permission_bits & self.STICKY:
                continue
            if ctx.dry_run:
                changed.append(directory)
                continue
            try:
                ctx.system.chmod(directory, info.permission_bits | self.STICKY)
            except OSError as exc:
                return RemediationRecord(
                    RemediationOutcome.FAILED, f"chmod +t failed on {directory}: {exc}"
                )
            changed.append(directory)
        if not changed:
            return RemediationRecord(RemediationOutcome.SKIPPED, "sticky bit already set")
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would set the sticky bit on: {', '.join(changed)}",
                changed_paths=tuple(changed),
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"sticky bit set on: {', '.join(changed)}",
            changed_paths=tuple(changed),
        )


class SeparateTmpPartitionCheck(Check):
    metadata = CheckMetadata(
        check_id="fs_tmp_separate_partition",
        title="/tmp is a separate mount with nodev,nosuid,noexec",
        description="/tmp should be its own mount point carrying hardening options.",
        severity=Severity.MEDIUM,
        rationale=(
            "A separate /tmp stops a runaway process filling the root filesystem, "
            "and nosuid/noexec prevent an attacker from staging and executing a "
            "payload in the one directory every user can write to."
        ),
        tags=FS_TAGS | {"cis", "mounts"},
        # Changing mount options requires editing fstab and remounting, which
        # can render a host unbootable. Reported only, deliberately.
        remediable=False,
        references=("CIS Ubuntu 24.04 1.1.2.1",),
    )

    REQUIRED_OPTIONS = ("nodev", "nosuid", "noexec")

    def audit(self, ctx: CheckContext) -> Finding:
        mounts = ctx.system.read_text("/proc/mounts")
        if mounts is None:
            return Finding.skipped("/proc/mounts is unavailable")

        entry = None
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "/tmp":
                entry = fields
        if entry is None:
            return Finding.failed(
                "/tmp is not a separate mount point", mount_point="/tmp", mounted=False
            )

        options = entry[3].split(",")
        missing = [opt for opt in self.REQUIRED_OPTIONS if opt not in options]
        evidence = {
            "device": entry[0],
            "fstype": entry[2],
            "options": options,
            "missing_options": missing,
        }
        if missing:
            return Finding.failed(
                f"/tmp is mounted but missing option(s): {', '.join(missing)}", **evidence
            )
        return Finding.passed(f"/tmp mounted with {', '.join(self.REQUIRED_OPTIONS)}", **evidence)


class WorldWritableFilesCheck(Check):
    metadata = CheckMetadata(
        check_id="fs_no_world_writable_in_etc",
        title="No world-writable files in /etc",
        description="Files under /etc must not be writable by all users.",
        severity=Severity.HIGH,
        rationale=(
            "A world-writable file in /etc is a configuration takeover: an "
            "unprivileged user edits it and waits for a privileged process to "
            "read it."
        ),
        tags=FS_TAGS | {"cis"},
        remediable=False,
        references=("CIS Ubuntu 24.04 6.1.9",),
    )

    WORLD_WRITABLE = 0o002
    # Bounded scan: top level plus one directory deep. A full recursive walk of
    # /etc as root on every scrape is an I/O cost we are not willing to pay on a
    # monitored host, and these two levels cover the real-world cases.
    PATTERNS = ("/etc/*", "/etc/*/*")

    def audit(self, ctx: CheckContext) -> Finding:
        offenders: list[dict[str, object]] = []
        scanned = 0
        for pattern in self.PATTERNS:
            for path in ctx.system.glob(pattern):
                info = ctx.system.stat(path)
                if info is None or info.is_symlink or info.is_dir:
                    continue
                scanned += 1
                if info.permission_bits & self.WORLD_WRITABLE:
                    offenders.append({"path": path, "mode": f"{info.permission_bits:04o}"})
        if scanned == 0:
            return Finding.skipped("/etc could not be enumerated")
        if offenders:
            names = ", ".join(str(o["path"]) for o in offenders[:10])
            return Finding.failed(
                f"{len(offenders)} world-writable file(s) under /etc: {names}",
                offenders=offenders,
                scanned=scanned,
            )
        return Finding.passed(f"no world-writable files among {scanned} scanned", scanned=scanned)


CHECKS = (
    PasswdPermissionsCheck,
    ShadowPermissionsCheck,
    GshadowPermissionsCheck,
    GroupPermissionsCheck,
    CrontabPermissionsCheck,
    SudoersPermissionsCheck,
    TmpStickyBitCheck,
    SeparateTmpPartitionCheck,
    WorldWritableFilesCheck,
)
