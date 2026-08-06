"""Check catalogue.

Registration is explicit rather than auto-discovered via ``pkgutil``. Importing
every module in a package and instantiating whatever looks like a check is
convenient right up to the point where a half-finished file silently changes the
security posture reported for a fleet. An explicit tuple means adding a control
is a reviewable one-line diff.
"""

from __future__ import annotations

from .accounts import CHECKS as ACCOUNT_CHECKS
from .base import (
    Check,
    CheckContext,
    FilePermissionCheck,
    RemediationNotSupportedError,
    SSHOptionCheck,
    SysctlCheck,
)
from .filesystem import CHECKS as FILESYSTEM_CHECKS
from .kernel import CHECKS as KERNEL_CHECKS
from .services import CHECKS as SERVICE_CHECKS
from .ssh import CHECKS as SSH_CHECKS

ALL_CHECK_CLASSES: tuple[type[Check], ...] = (
    *SSH_CHECKS,
    *KERNEL_CHECKS,
    *FILESYSTEM_CHECKS,
    *ACCOUNT_CHECKS,
    *SERVICE_CHECKS,
)

__all__ = [
    "ALL_CHECK_CLASSES",
    "Check",
    "CheckContext",
    "FilePermissionCheck",
    "RemediationNotSupportedError",
    "SSHOptionCheck",
    "SysctlCheck",
]
