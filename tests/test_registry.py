"""Registry registration and selection semantics."""

from __future__ import annotations

import pytest

from hardening_agent.checks.base import Check, CheckContext
from hardening_agent.config import AuditConfig
from hardening_agent.models import CheckMetadata, Finding, Severity
from hardening_agent.registry import CheckRegistry, DuplicateCheckError, UnknownCheckError


def make_check(
    check_id: str,
    severity: Severity = Severity.MEDIUM,
    tags: frozenset[str] = frozenset(),
) -> Check:
    class _Check(Check):
        metadata = CheckMetadata(
            check_id=check_id,
            title=f"Title {check_id}",
            description="d",
            severity=severity,
            rationale="r",
            tags=tags,
        )

        def audit(self, ctx: CheckContext) -> Finding:
            return Finding.passed("ok")

    return _Check()


class TestRegistration:
    def test_duplicate_ids_are_rejected(self) -> None:
        """Two checks with one id would silently overwrite in Prometheus."""
        registry = CheckRegistry([make_check("a")])
        with pytest.raises(DuplicateCheckError, match="duplicate check_id"):
            registry.register(make_check("a"))

    def test_membership_and_length(self) -> None:
        registry = CheckRegistry([make_check("a"), make_check("b")])
        assert len(registry) == 2
        assert "a" in registry
        assert "z" not in registry

    def test_get_unknown_raises(self) -> None:
        with pytest.raises(UnknownCheckError, match="no such check"):
            CheckRegistry().get("missing")


class TestDefaultCatalogue:
    def test_builds_without_error(self) -> None:
        assert len(CheckRegistry.with_defaults()) > 0

    def test_every_check_has_complete_metadata(self) -> None:
        """A check without a rationale cannot be acted on by whoever reads it."""
        for check in CheckRegistry.with_defaults():
            meta = check.metadata
            assert meta.title, f"{meta.check_id} has no title"
            assert meta.description, f"{meta.check_id} has no description"
            assert meta.rationale, f"{meta.check_id} has no rationale"
            assert meta.tags, f"{meta.check_id} has no tags"
            assert len(meta.rationale) > 40, f"{meta.check_id} rationale is too thin"

    def test_risky_remediation_implies_remediable(self) -> None:
        for check in CheckRegistry.with_defaults():
            meta = check.metadata
            if meta.risky_remediation:
                assert meta.remediable, f"{meta.check_id} is risky but not remediable"

    def test_remediable_checks_override_remediate(self) -> None:
        """Metadata claiming remediable must be backed by an implementation."""
        for check in CheckRegistry.with_defaults():
            if check.metadata.remediable:
                assert type(check).remediate is not Check.remediate, (
                    f"{check.metadata.check_id} claims remediable but inherits the stub"
                )


class TestSelection:
    @pytest.fixture
    def registry(self) -> CheckRegistry:
        return CheckRegistry(
            [
                make_check("low_a", Severity.LOW, frozenset({"ssh"})),
                make_check("med_b", Severity.MEDIUM, frozenset({"kernel"})),
                make_check("high_c", Severity.HIGH, frozenset({"ssh", "kernel"})),
                make_check("crit_d", Severity.CRITICAL, frozenset({"accounts"})),
            ]
        )

    def test_default_selects_everything(self, registry: CheckRegistry) -> None:
        assert len(registry.select(AuditConfig())) == 4

    def test_min_severity_filters(self, registry: CheckRegistry) -> None:
        selected = registry.select(AuditConfig(min_severity=Severity.HIGH))
        assert {c.check_id for c in selected} == {"high_c", "crit_d"}

    def test_include_is_a_whitelist(self, registry: CheckRegistry) -> None:
        selected = registry.select(AuditConfig(include=("low_a",)))
        assert [c.check_id for c in selected] == ["low_a"]

    def test_tags_match_any(self, registry: CheckRegistry) -> None:
        selected = registry.select(AuditConfig(tags=("ssh",)))
        assert {c.check_id for c in selected} == {"low_a", "high_c"}

    def test_exclude_wins_over_tags(self, registry: CheckRegistry) -> None:
        """An operator who excluded a noisy check must not get it back via a tag."""
        selected = registry.select(AuditConfig(tags=("ssh",), exclude=("low_a",)))
        assert [c.check_id for c in selected] == ["high_c"]

    def test_filters_compose(self, registry: CheckRegistry) -> None:
        selected = registry.select(
            AuditConfig(tags=("ssh", "kernel"), min_severity=Severity.MEDIUM)
        )
        assert {c.check_id for c in selected} == {"med_b", "high_c"}

    def test_ordering_is_severity_then_id(self, registry: CheckRegistry) -> None:
        """Deterministic order keeps report diffs reviewable."""
        selected = registry.select(AuditConfig())
        assert [c.check_id for c in selected] == ["crit_d", "high_c", "med_b", "low_a"]

    def test_unknown_include_id_raises(self, registry: CheckRegistry) -> None:
        with pytest.raises(UnknownCheckError, match="unknown check id"):
            registry.select(AuditConfig(include=("does_not_exist",)))

    def test_unknown_exclude_id_raises(self, registry: CheckRegistry) -> None:
        """Typo'd exclusions must fail loudly, not silently apply no filter."""
        with pytest.raises(UnknownCheckError):
            registry.select(AuditConfig(exclude=("typo_here",)))


class TestIntrospection:
    def test_all_tags_sorted_and_deduplicated(self) -> None:
        registry = CheckRegistry(
            [
                make_check("a", tags=frozenset({"z", "a"})),
                make_check("b", tags=frozenset({"a", "m"})),
            ]
        )
        assert registry.all_tags() == ("a", "m", "z")

    def test_severity_histogram_covers_all_levels(self) -> None:
        registry = CheckRegistry([make_check("a", Severity.HIGH)])
        histogram = registry.severity_histogram()
        assert histogram == {"low": 0, "medium": 0, "high": 1, "critical": 0}
