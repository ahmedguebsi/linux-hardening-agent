"""Audit and remediation execution.

Design rules enforced here:

* **One check can never abort the run.** Every check is executed inside a
  try/except that converts any exception into ``Status.ERROR``. A security audit
  that silently stops halfway is worse than one that reports a broken control.
* **Remediation only follows a FAIL.** The runner re-audits after remediating so
  the report reflects the post-remediation state, not the pre-remediation one.
* **The runner owns timing and metadata.** Checks stay small and declarative.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from .backup import BackupManager
from .checks import Check, CheckContext, RemediationNotSupportedError
from .config import Config
from .logging_setup import get_logger
from .models import (
    CheckResult,
    Finding,
    RemediationOutcome,
    RemediationRecord,
    Report,
    Severity,
    Status,
)
from .registry import CheckRegistry
from .system import SystemInterface

logger = get_logger("runner")


class AuditRunner:
    """Executes checks and assembles a :class:`Report`."""

    def __init__(
        self,
        registry: CheckRegistry,
        system: SystemInterface,
        config: Config,
        *,
        agent_version: str,
    ) -> None:
        self._registry = registry
        self._system = system
        self._config = config
        self._agent_version = agent_version
        self._backup = BackupManager(
            system,
            config.remediation.backup_dir,
            keep=config.remediation.keep_backups,
        )

    @property
    def system(self) -> SystemInterface:
        """The host interface in use. Exposed so callers can collect telemetry
        against the same (possibly faked) system the audit ran against."""
        return self._system

    def run(self, *, remediate: bool = False, dry_run: bool = False) -> Report:
        """Audit the host, optionally remediating failures."""
        checks = self._registry.select(self._config.audit)
        started = time.time()
        logger.info(
            "audit started",
            extra={
                "checks": len(checks),
                "profile": self._config.audit.profile,
                "remediate": remediate,
                "dry_run": dry_run,
            },
        )

        ctx = CheckContext(
            system=self._system,
            backup=self._backup,
            dry_run=dry_run,
            allow_risky=self._config.remediation.allow_risky,
        )

        results = [self._execute(check, ctx, remediate=remediate) for check in checks]
        finished = time.time()

        report = Report(
            host=self._system.host_info(),
            results=tuple(results),
            started_at=started,
            finished_at=finished,
            agent_version=self._agent_version,
            profile=self._config.audit.profile,
            dry_run=dry_run,
        )
        counts = report.counts()
        logger.info(
            "audit finished",
            extra={
                "duration_ms": round(report.duration_ms, 1),
                "score": report.score(),
                **{f"count_{k}": v for k, v in counts.items()},
            },
        )
        return report

    def _execute(self, check: Check, ctx: CheckContext, *, remediate: bool) -> CheckResult:
        meta = check.metadata
        started = time.perf_counter()
        finding = self._safe_audit(check, ctx)
        remediation: RemediationRecord | None = None

        if remediate and finding.status is Status.FAIL:
            remediation = self._safe_remediate(check, ctx)
            # Re-audit so the report shows reality after the change. Without
            # this, a report can claim a control failed while it now passes.
            if remediation.outcome is RemediationOutcome.APPLIED:
                finding = self._safe_audit(check, ctx)

        duration_ms = (time.perf_counter() - started) * 1000.0
        log_extra: dict[str, Any] = {
            "check_id": meta.check_id,
            "status": finding.status.value,
            "severity": meta.severity.value,
            "duration_ms": round(duration_ms, 2),
        }
        if self._config.logging.include_evidence:
            log_extra["evidence"] = dict(finding.evidence)
        if finding.status is Status.FAIL:
            logger.warning(finding.detail, extra=log_extra)
        elif finding.status is Status.ERROR:
            logger.error(finding.detail, extra=log_extra)
        else:
            logger.debug(finding.detail, extra=log_extra)

        return CheckResult(
            metadata=meta,
            status=finding.status,
            detail=finding.detail,
            evidence=finding.evidence,
            duration_ms=duration_ms,
            remediation=remediation,
        )

    def _safe_audit(self, check: Check, ctx: CheckContext) -> Finding:
        try:
            return check.audit(ctx)
        except Exception as exc:
            logger.exception(
                "check raised an exception",
                extra={"check_id": check.metadata.check_id, "error": str(exc)},
            )
            return Finding.errored(
                f"check raised {type(exc).__name__}: {exc}", exception=type(exc).__name__
            )

    def _safe_remediate(self, check: Check, ctx: CheckContext) -> RemediationRecord:
        meta = check.metadata
        if not meta.remediable:
            return RemediationRecord(
                RemediationOutcome.UNSUPPORTED,
                f"{meta.check_id} has no automated remediation; see the runbook",
            )
        if meta.risky_remediation and not ctx.allow_risky:
            return RemediationRecord(
                RemediationOutcome.SKIPPED,
                f"{meta.check_id} is flagged risky_remediation; re-run with --allow-risky",
            )
        if not ctx.dry_run and not self._system.is_root():
            return RemediationRecord(
                RemediationOutcome.SKIPPED, "remediation requires root privileges"
            )
        try:
            record = check.remediate(ctx)
        except RemediationNotSupportedError as exc:
            return RemediationRecord(RemediationOutcome.UNSUPPORTED, str(exc))
        except Exception as exc:
            logger.exception(
                "remediation raised an exception",
                extra={"check_id": meta.check_id, "error": str(exc)},
            )
            return RemediationRecord(
                RemediationOutcome.FAILED, f"remediation raised {type(exc).__name__}: {exc}"
            )
        logger.info(
            "remediation completed",
            extra={
                "check_id": meta.check_id,
                "outcome": record.outcome.value,
                "backup_id": record.backup_id,
            },
        )
        return record


# Exit codes are part of the CLI contract; CI pipelines depend on them.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_USAGE = 3


def determine_exit_code(report: Report, fail_on: Severity) -> int:
    """Map a report to a process exit code.

    Check *errors* outrank findings: a broken check means the host's posture is
    unknown, which a pipeline must not treat as "merely non-compliant".
    """
    if report.errors():
        return EXIT_ERROR
    worst = report.worst_failed_severity()
    if worst is not None and worst.rank >= fail_on.rank:
        return EXIT_FINDINGS
    return EXIT_OK


def summarise(results: Sequence[CheckResult]) -> dict[str, int]:
    """Count results by status. Used by the metrics layer and the text report."""
    counts = {status.value: 0 for status in Status}
    for result in results:
        counts[result.status.value] += 1
    return counts
