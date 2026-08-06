"""Check abstraction and reusable check families.

A check is a small object with static :class:`~hardening_agent.models.CheckMetadata`
and an :meth:`Check.audit` method. Checks are pure with respect to the host: they
read through :class:`~hardening_agent.system.SystemInterface` and return a
:class:`~hardening_agent.models.Finding`. They never log at ERROR, never exit,
and never raise for an expected condition -- the runner turns exceptions into
``Status.ERROR`` so one broken check cannot abort an audit.

The parameterised base classes at the bottom (``SysctlCheck``,
``FilePermissionCheck``, ``SSHOptionCheck``) exist because ~70% of a CIS-style
baseline is the same three shapes repeated. Encoding the shape once means a new
control is a five-line subclass, and the tricky parsing is tested in one place.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Final

from ..backup import BackupManager
from ..models import (
    CheckMetadata,
    Finding,
    RemediationOutcome,
    RemediationRecord,
    Severity,
)
from ..system import SystemInterface

SYSCTL_CONF_PATH: Final = "/etc/sysctl.d/99-hardening-agent.conf"


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Everything a check is allowed to touch."""

    system: SystemInterface
    backup: BackupManager
    dry_run: bool = False
    allow_risky: bool = False


class RemediationNotSupportedError(RuntimeError):
    """Raised when ``remediate`` is called on an audit-only check."""


class Check(ABC):
    """Base class for all controls.

    Subclasses that exist only to be subclassed further (the reusable families
    below) pass ``family=True`` so they are exempt from the metadata
    requirement. Every concrete control must declare ``metadata``; enforcing it
    at class-creation time turns "someone forgot the docs" into an import error
    that CI catches, rather than a report with a blank row.
    """

    metadata: ClassVar[CheckMetadata]
    is_family: ClassVar[bool] = False

    def __init_subclass__(cls, *, family: bool = False, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls.is_family = family
        if family:
            return
        if "metadata" not in cls.__dict__:
            raise TypeError(
                f"{cls.__name__} must define a `metadata` class attribute "
                f"(or pass family=True if it is an abstract base)"
            )

    @property
    def check_id(self) -> str:
        return self.metadata.check_id

    @abstractmethod
    def audit(self, ctx: CheckContext) -> Finding:
        """Observe the host and report. Must not modify anything."""

    def remediate(self, ctx: CheckContext) -> RemediationRecord:  # noqa: ARG002
        """Bring the host into compliance. Only called after a FAIL.

        The default refuses. A check is remediable only if it overrides this and
        declares ``remediable=True`` in its metadata; the registry test asserts
        those two facts stay in sync.
        """
        raise RemediationNotSupportedError(f"{self.check_id} does not support remediation")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.check_id}>"


# ---------------------------------------------------------------------------
# sysctl family
# ---------------------------------------------------------------------------
def read_sysctl(system: SystemInterface, key: str) -> str | None:
    """Read the *runtime* value of a sysctl key.

    We read ``/proc/sys/...`` rather than parsing ``/etc/sysctl.conf`` because
    the running kernel is the ground truth. A config file can say one thing while
    the live kernel says another -- and it is the live kernel that an attacker
    faces.
    """
    path = "/proc/sys/" + key.replace(".", "/")
    content = system.read_text(path)
    return content.strip() if content is not None else None


class SysctlCheck(Check, family=True):
    """Assert that a kernel parameter has an expected runtime value."""

    sysctl_key: ClassVar[str]
    expected: ClassVar[str]

    def audit(self, ctx: CheckContext) -> Finding:
        actual = read_sysctl(ctx.system, self.sysctl_key)
        if actual is None:
            return Finding.skipped(
                f"sysctl {self.sysctl_key} is not exposed by this kernel",
                sysctl=self.sysctl_key,
            )
        # Kernels render some values with tabs/multiple spaces (e.g. tcp_rmem).
        normalised = " ".join(actual.split())
        if normalised == self.expected:
            return Finding.passed(
                f"{self.sysctl_key} = {normalised}",
                sysctl=self.sysctl_key,
                actual=normalised,
                expected=self.expected,
            )
        return Finding.failed(
            f"{self.sysctl_key} = {normalised}, expected {self.expected}",
            sysctl=self.sysctl_key,
            actual=normalised,
            expected=self.expected,
        )

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        """Persist the setting to a drop-in file and apply it at runtime.

        Both steps are required: writing the file alone leaves the host exposed
        until reboot, and ``sysctl -w`` alone is lost on reboot.
        """
        line = f"{self.sysctl_key} = {self.expected}"
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would write '{line}' to {SYSCTL_CONF_PATH} and apply it",
                changed_paths=(SYSCTL_CONF_PATH,),
            )

        ctx.backup.backup_file(SYSCTL_CONF_PATH)
        existing = ctx.system.read_text(SYSCTL_CONF_PATH) or (
            "# Managed by hardening-agent. Manual edits may be overwritten.\n"
        )
        updated = _upsert_sysctl_line(existing, self.sysctl_key, self.expected)
        ctx.system.write_text(SYSCTL_CONF_PATH, updated, mode=0o644)

        result = ctx.system.run(["sysctl", "-w", f"{self.sysctl_key}={self.expected}"])
        if not result.ok:
            ctx.backup.restore_set()
            return RemediationRecord(
                RemediationOutcome.ROLLED_BACK,
                f"sysctl -w failed ({result.stderr.strip()}); configuration restored",
                changed_paths=(SYSCTL_CONF_PATH,),
                backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
                commands=(result.display,),
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"set {line} and persisted to {SYSCTL_CONF_PATH}",
            changed_paths=(SYSCTL_CONF_PATH,),
            backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
            commands=(result.display,),
        )


def _upsert_sysctl_line(content: str, key: str, value: str) -> str:
    """Replace an existing ``key = value`` line or append a new one."""
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=.*$", re.MULTILINE)
    replacement = f"{key} = {value}"
    if pattern.search(content):
        return pattern.sub(replacement, content)
    if content and not content.endswith("\n"):
        content += "\n"
    return f"{content}{replacement}\n"


# ---------------------------------------------------------------------------
# file permission family
# ---------------------------------------------------------------------------
class FilePermissionCheck(Check, family=True):
    """Assert a file's mode is no more permissive than a maximum, plus ownership."""

    target_path: ClassVar[str]
    max_mode: ClassVar[int]
    expected_uid: ClassVar[int | None] = 0
    expected_gid: ClassVar[int | None] = None
    required: ClassVar[bool] = True

    def audit(self, ctx: CheckContext) -> Finding:
        info = ctx.system.stat(self.target_path)
        if info is None:
            if self.required:
                return Finding.failed(
                    f"{self.target_path} is missing", path=self.target_path, present=False
                )
            return Finding.skipped(
                f"{self.target_path} is not present on this host", path=self.target_path
            )

        bits = info.permission_bits
        problems: list[str] = []
        # An overly permissive file has bits set that the maximum does not allow.
        if bits & ~self.max_mode:
            problems.append(f"mode {bits:04o} is more permissive than {self.max_mode:04o}")
        if self.expected_uid is not None and info.uid != self.expected_uid:
            problems.append(f"owner uid {info.uid}, expected {self.expected_uid}")
        if self.expected_gid is not None and info.gid != self.expected_gid:
            problems.append(f"group gid {info.gid}, expected {self.expected_gid}")

        evidence = {
            "path": self.target_path,
            "mode": f"{bits:04o}",
            "max_mode": f"{self.max_mode:04o}",
            "uid": info.uid,
            "gid": info.gid,
        }
        if problems:
            return Finding.failed("; ".join(problems), **evidence)
        return Finding.passed(f"{self.target_path} mode {bits:04o} uid {info.uid}", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        info = ctx.system.stat(self.target_path)
        if info is None:
            return RemediationRecord(
                RemediationOutcome.SKIPPED, f"{self.target_path} does not exist"
            )
        target_mode = info.permission_bits & self.max_mode
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would chmod {target_mode:04o} {self.target_path}",
                changed_paths=(self.target_path,),
            )
        ctx.backup.backup_file(self.target_path)
        try:
            ctx.system.chmod(self.target_path, target_mode)
        except OSError as exc:
            return RemediationRecord(
                RemediationOutcome.FAILED, f"chmod failed: {exc}", (self.target_path,)
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"mode tightened to {target_mode:04o}",
            changed_paths=(self.target_path,),
            backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
        )


# ---------------------------------------------------------------------------
# sshd_config family
# ---------------------------------------------------------------------------
SSHD_CONFIG_PATH: Final = "/etc/ssh/sshd_config"
_INCLUDE_RE = re.compile(r"^\s*include\s+(.+?)\s*$", re.IGNORECASE)


def load_sshd_directives(
    system: SystemInterface, path: str = SSHD_CONFIG_PATH, *, _depth: int = 0
) -> dict[str, str] | None:
    """Return the *effective* sshd options, honouring ``Include`` directives.

    OpenSSH semantics: the **first** occurrence of a keyword wins, and ``Include``
    is expanded in place. Ubuntu ships ``Include /etc/ssh/sshd_config.d/*.conf``
    at the top of the file precisely so drop-ins override the main config, so
    getting the ordering right is what makes this check correct on a stock host.

    ``Match`` blocks are deliberately ignored -- options inside them are
    conditional and cannot be evaluated without a connection context. Callers get
    the global values only, which is the conservative reading for an audit.
    """
    if _depth > 8:  # cycle guard
        return {}
    content = system.read_text(path)
    if content is None:
        return None

    directives: dict[str, str] = {}
    in_match_block = False

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        keyword = line.split(None, 1)[0].lower()
        if keyword == "match":
            in_match_block = True
            continue
        if in_match_block:
            # Everything after a Match applies conditionally; skip to end of file.
            continue

        if (include := _INCLUDE_RE.match(line)) is not None:
            for pattern in include.group(1).split():
                absolute = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                for included in system.glob(absolute):
                    nested = load_sshd_directives(system, included, _depth=_depth + 1) or {}
                    for key, value in nested.items():
                        directives.setdefault(key, value)
            continue

        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        directives.setdefault(parts[0].lower(), parts[1].strip())

    return directives


class SSHOptionCheck(Check, family=True):
    """Assert an sshd option is set to one of the accepted values."""

    option: ClassVar[str]
    accepted: ClassVar[frozenset[str]]
    desired: ClassVar[str]
    # OpenSSH's compiled-in default when the option is absent from the config.
    implicit_default: ClassVar[str | None] = None

    def audit(self, ctx: CheckContext) -> Finding:
        directives = load_sshd_directives(ctx.system)
        if directives is None:
            return Finding.skipped(
                f"{SSHD_CONFIG_PATH} not found; host does not appear to run sshd",
                path=SSHD_CONFIG_PATH,
            )
        actual = directives.get(self.option.lower())
        effective = actual if actual is not None else self.implicit_default
        evidence = {
            "option": self.option,
            "configured": actual,
            "effective": effective,
            "accepted": sorted(self.accepted),
        }
        if effective is None:
            return Finding.failed(
                f"{self.option} is not set and has no safe default; expected {self.desired}",
                **evidence,
            )
        if effective.lower() in {value.lower() for value in self.accepted}:
            source = "configured" if actual is not None else "OpenSSH default"
            return Finding.passed(f"{self.option} = {effective} ({source})", **evidence)
        return Finding.failed(f"{self.option} = {effective}, expected {self.desired}", **evidence)

    def remediate(self, ctx: CheckContext) -> RemediationRecord:
        """Rewrite the option, validate with ``sshd -t``, and roll back on error.

        Validating before reload is non-negotiable: a malformed ``sshd_config``
        that gets reloaded can end remote access to the host permanently.
        """
        if ctx.dry_run:
            return RemediationRecord(
                RemediationOutcome.DRY_RUN,
                f"would set '{self.option} {self.desired}' in {SSHD_CONFIG_PATH}",
                changed_paths=(SSHD_CONFIG_PATH,),
            )

        content = ctx.system.read_text(SSHD_CONFIG_PATH)
        if content is None:
            return RemediationRecord(RemediationOutcome.SKIPPED, f"{SSHD_CONFIG_PATH} not present")

        ctx.backup.backup_file(SSHD_CONFIG_PATH)
        updated = _upsert_ssh_option(content, self.option, self.desired)
        ctx.system.write_text(SSHD_CONFIG_PATH, updated, mode=0o600)

        validation = ctx.system.run(["sshd", "-t"])
        if not validation.ok:
            ctx.backup.restore_set()
            return RemediationRecord(
                RemediationOutcome.ROLLED_BACK,
                f"sshd -t rejected the new config ({validation.stderr.strip()}); restored",
                changed_paths=(SSHD_CONFIG_PATH,),
                backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
                commands=(validation.display,),
            )

        reload_result = ctx.system.run(["systemctl", "reload", "ssh"])
        commands = (validation.display, reload_result.display)
        if not reload_result.ok:
            # The file is valid; a failed reload just means the new setting is
            # not live yet. Do not roll back -- leave it for the next restart.
            return RemediationRecord(
                RemediationOutcome.APPLIED,
                f"config updated and validated; reload failed "
                f"({reload_result.stderr.strip()}), change applies on next sshd restart",
                changed_paths=(SSHD_CONFIG_PATH,),
                backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
                commands=commands,
            )
        return RemediationRecord(
            RemediationOutcome.APPLIED,
            f"set '{self.option} {self.desired}', validated and reloaded sshd",
            changed_paths=(SSHD_CONFIG_PATH,),
            backup_id=ctx.backup.current.backup_id if ctx.backup.current else None,
            commands=commands,
        )


def _upsert_ssh_option(content: str, option: str, value: str) -> str:
    """Set an sshd option, commenting out any pre-existing occurrences.

    Existing lines are commented rather than deleted so an operator reviewing the
    file can see what the agent changed and why the original value was.
    """
    pattern = re.compile(rf"^(\s*)({re.escape(option)})(\s+)(.*)$", re.IGNORECASE | re.MULTILINE)
    replaced = pattern.sub(
        lambda m: f"# hardening-agent: was '{m.group(2)}{m.group(3)}{m.group(4)}'", content
    )
    if replaced and not replaced.endswith("\n"):
        replaced += "\n"
    return f"{replaced}\n# hardening-agent managed\n{option} {value}\n"


def severity_for(name: str) -> Severity:
    """Small helper so check modules read declaratively."""
    return Severity.parse(name)


__all__ = [
    "SSHD_CONFIG_PATH",
    "SYSCTL_CONF_PATH",
    "Check",
    "CheckContext",
    "CheckMetadata",
    "FilePermissionCheck",
    "Finding",
    "RemediationNotSupportedError",
    "SSHOptionCheck",
    "SysctlCheck",
    "load_sshd_directives",
    "read_sysctl",
    "severity_for",
]
