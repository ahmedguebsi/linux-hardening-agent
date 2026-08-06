"""Core domain types for the hardening agent.

These types are deliberately free of I/O and framework dependencies so that they
can be constructed in tests without touching a real host. Every type is either
frozen or explicitly documented as mutable, which makes the audit pipeline easy
to reason about: checks produce values, the runner aggregates values, and the
reporters serialise values.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Self


class Severity(StrEnum):
    """Impact of a failing check.

    Ordered so that callers can filter with ``>=`` semantics via :attr:`rank`.
    ``StrEnum`` means these serialise to JSON and format into metric labels as
    their plain value, with no custom encoder anywhere.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Self:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:  # pragma: no cover - exercised via config tests
            valid = ", ".join(item.value for item in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Status(StrEnum):
    """Outcome of a single check execution.

    ``SKIP`` means the check did not apply to this host (for example an SSH check
    on a host without an sshd config). ``ERROR`` means the check itself failed to
    execute. Keeping those distinct from ``FAIL`` matters: a broken check must
    never be reported as a passing or failing control.
    """

    PASS = "pass"  # noqa: S105 - an audit outcome, not a credential
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"

    @property
    def is_actionable(self) -> bool:
        return self in (Status.FAIL, Status.ERROR)


class RemediationOutcome(StrEnum):
    """Result of attempting to remediate a failing check."""

    APPLIED = "applied"
    DRY_RUN = "dry_run"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class CheckMetadata:
    """Static description of a control.

    Metadata is separated from results so the catalogue can be listed, exported
    to documentation, and diffed in review without executing anything.
    """

    check_id: str
    title: str
    description: str
    severity: Severity
    rationale: str
    tags: frozenset[str] = frozenset()
    remediable: bool = False
    risky_remediation: bool = False
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.check_id:
            raise ValueError("check_id must not be empty")
        if not self.check_id.replace("_", "").replace("-", "").isalnum():
            raise ValueError(
                f"check_id {self.check_id!r} must be alphanumeric with '_' or '-' separators"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "rationale": self.rationale,
            "tags": sorted(self.tags),
            "remediable": self.remediable,
            "risky_remediation": self.risky_remediation,
            "references": list(self.references),
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """What a check observed. Returned by ``Check.audit``.

    Checks return a ``Finding`` rather than a full ``CheckResult`` so they never
    have to restate their own metadata or measure their own runtime; the runner
    owns both. ``evidence`` should carry the raw observed values so that a report
    is self-explanatory without re-running the agent.
    """

    status: Status
    detail: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def passed(cls, detail: str, **evidence: Any) -> Finding:
        return cls(Status.PASS, detail, evidence)

    @classmethod
    def failed(cls, detail: str, **evidence: Any) -> Finding:
        return cls(Status.FAIL, detail, evidence)

    @classmethod
    def skipped(cls, detail: str, **evidence: Any) -> Finding:
        return cls(Status.SKIP, detail, evidence)

    @classmethod
    def errored(cls, detail: str, **evidence: Any) -> Finding:
        return cls(Status.ERROR, detail, evidence)


@dataclass(frozen=True, slots=True)
class RemediationRecord:
    """Audit trail for a remediation attempt."""

    outcome: RemediationOutcome
    detail: str
    changed_paths: tuple[str, ...] = ()
    backup_id: str | None = None
    commands: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "detail": self.detail,
            "changed_paths": list(self.changed_paths),
            "backup_id": self.backup_id,
            "commands": list(self.commands),
        }


@dataclass(frozen=True, slots=True)
class CheckResult:
    """A finding joined with its metadata and execution telemetry."""

    metadata: CheckMetadata
    status: Status
    detail: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    remediation: RemediationRecord | None = None

    @property
    def check_id(self) -> str:
        return self.metadata.check_id

    @property
    def severity(self) -> Severity:
        return self.metadata.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.metadata.to_dict(),
            "status": self.status.value,
            "detail": self.detail,
            "evidence": dict(self.evidence),
            "duration_ms": round(self.duration_ms, 3),
            "remediation": self.remediation.to_dict() if self.remediation else None,
        }


@dataclass(frozen=True, slots=True)
class HostInfo:
    """Identity of the audited host, embedded in every report and metric."""

    hostname: str
    os_name: str
    os_version: str
    kernel: str
    architecture: str
    virtualization: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "virtualization": self.virtualization,
        }


@dataclass(frozen=True, slots=True)
class Report:
    """Aggregate result of one agent run."""

    host: HostInfo
    results: tuple[CheckResult, ...]
    started_at: float
    finished_at: float
    agent_version: str
    profile: str
    dry_run: bool = False

    @property
    def duration_ms(self) -> float:
        return (self.finished_at - self.started_at) * 1000.0

    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in Status}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(r for r in self.results if r.status is Status.FAIL)

    def errors(self) -> tuple[CheckResult, ...]:
        return tuple(r for r in self.results if r.status is Status.ERROR)

    def worst_failed_severity(self) -> Severity | None:
        failed = self.failures()
        if not failed:
            return None
        return max((r.severity for r in failed), key=lambda s: s.rank)

    def score(self) -> float:
        """Percentage of applicable (non-skipped, non-errored) checks that passed.

        Skipped checks are excluded rather than counted as passes, otherwise a
        host with most controls inapplicable would score misleadingly well.
        """
        applicable = [r for r in self.results if r.status in (Status.PASS, Status.FAIL)]
        if not applicable:
            return 100.0
        passed = sum(1 for r in applicable if r.status is Status.PASS)
        return round(passed / len(applicable) * 100.0, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "agent_version": self.agent_version,
            "profile": self.profile,
            "dry_run": self.dry_run,
            "host": self.host.to_dict(),
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "duration_ms": round(self.duration_ms, 3),
            "score": self.score(),
            "counts": self.counts(),
            "results": [r.to_dict() for r in self.results],
        }


REPORT_SCHEMA_VERSION = "1.0"


def _iso(epoch: float) -> str:
    """RFC3339-ish UTC timestamp. Stable across locales and TZ settings."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
