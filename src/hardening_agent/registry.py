"""Check registry and selection logic.

The registry owns two responsibilities that are easy to get wrong if scattered:
duplicate-id detection (two checks reporting under the same metric label would
silently overwrite each other in Prometheus) and deterministic ordering (a report
whose row order changes between runs is unreviewable in a diff).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .checks import ALL_CHECK_CLASSES, Check
from .config import AuditConfig
from .logging_setup import get_logger
from .models import Severity

logger = get_logger("registry")


class DuplicateCheckError(ValueError):
    """Raised when two checks share a ``check_id``."""


class UnknownCheckError(KeyError):
    """Raised when a selector names a check that does not exist."""


class CheckRegistry:
    """An ordered, unique collection of check instances."""

    def __init__(self, checks: Iterable[Check] = ()) -> None:
        self._checks: dict[str, Check] = {}
        for check in checks:
            self.register(check)

    @classmethod
    def with_defaults(cls) -> CheckRegistry:
        """Build a registry containing the full built-in catalogue."""
        return cls(check_class() for check_class in ALL_CHECK_CLASSES)

    def register(self, check: Check) -> None:
        check_id = check.metadata.check_id
        if check_id in self._checks:
            raise DuplicateCheckError(
                f"duplicate check_id {check_id!r}: "
                f"{type(self._checks[check_id]).__name__} and {type(check).__name__}"
            )
        self._checks[check_id] = check

    def get(self, check_id: str) -> Check:
        try:
            return self._checks[check_id]
        except KeyError as exc:
            raise UnknownCheckError(f"no such check: {check_id!r}") from exc

    def __len__(self) -> int:
        return len(self._checks)

    def __iter__(self) -> Iterator[Check]:
        return iter(self._checks.values())

    def __contains__(self, check_id: object) -> bool:
        return check_id in self._checks

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(self._checks)

    def all_tags(self) -> tuple[str, ...]:
        tags: set[str] = set()
        for check in self._checks.values():
            tags |= check.metadata.tags
        return tuple(sorted(tags))

    def select(self, config: AuditConfig) -> tuple[Check, ...]:
        """Resolve the configured filters into a concrete, ordered check list.

        Filters compose as: ``include`` (whitelist, if given) AND ``tags``
        (any-match, if given) AND ``min_severity``, then ``exclude`` removes.
        Exclusion is applied last so it always wins -- an operator who excluded a
        noisy check should never see it come back because it also matched a tag.
        """
        unknown = [cid for cid in (*config.include, *config.exclude) if cid not in self._checks]
        if unknown:
            raise UnknownCheckError(
                f"unknown check id(s): {sorted(unknown)}; "
                f"run `hardening-agent list-checks` to see valid ids"
            )

        selected: list[Check] = []
        wanted_tags = set(config.tags)
        for check in self._checks.values():
            meta = check.metadata
            if config.include and meta.check_id not in config.include:
                continue
            if wanted_tags and not (meta.tags & wanted_tags):
                continue
            if meta.severity.rank < config.min_severity.rank:
                continue
            if meta.check_id in config.exclude:
                continue
            selected.append(check)

        # Stable, meaningful ordering: most severe first, then id for ties.
        selected.sort(key=lambda c: (-c.metadata.severity.rank, c.metadata.check_id))
        logger.debug(
            "checks selected",
            extra={
                "selected": len(selected),
                "available": len(self._checks),
                "min_severity": config.min_severity.value,
                "tags": sorted(wanted_tags),
            },
        )
        return tuple(selected)

    def catalogue(self) -> list[dict[str, object]]:
        """Machine-readable listing of every registered check."""
        return [
            check.metadata.to_dict()
            for check in sorted(
                self._checks.values(),
                key=lambda c: (-c.metadata.severity.rank, c.metadata.check_id),
            )
        ]

    def severity_histogram(self) -> dict[str, int]:
        histogram = {severity.value: 0 for severity in Severity}
        for check in self._checks.values():
            histogram[check.metadata.severity.value] += 1
        return histogram
