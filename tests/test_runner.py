"""Runner orchestration: error isolation, remediation gating, exit codes."""

from __future__ import annotations

import pytest

from hardening_agent.checks.base import Check, CheckContext
from hardening_agent.config import AuditConfig, Config, RemediationConfig
from hardening_agent.models import (
    CheckMetadata,
    Finding,
    RemediationOutcome,
    RemediationRecord,
    Severity,
    Status,
)
from hardening_agent.registry import CheckRegistry
from hardening_agent.runner import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    AuditRunner,
    determine_exit_code,
)
from tests.conftest import FakeSystem
from tests.test_models import make_report


def build_check(
    check_id: str,
    finding: Finding | None = None,
    *,
    severity: Severity = Severity.HIGH,
    remediable: bool = False,
    risky: bool = False,
    raises: Exception | None = None,
    remediation: RemediationRecord | None = None,
    remediation_raises: Exception | None = None,
) -> Check:
    class _Check(Check):
        metadata = CheckMetadata(
            check_id=check_id,
            title=f"Title {check_id}",
            description="d",
            severity=severity,
            rationale="r",
            tags=frozenset({"test"}),
            remediable=remediable,
            risky_remediation=risky,
        )

        def __init__(self) -> None:
            self.audit_calls = 0

        def audit(self, ctx: CheckContext) -> Finding:
            self.audit_calls += 1
            if raises is not None:
                raise raises
            # After a successful remediation, report PASS on re-audit.
            if remediation is not None and self.audit_calls > 1:
                return Finding.passed("fixed")
            return finding or Finding.passed("ok")

        def remediate(self, ctx: CheckContext) -> RemediationRecord:
            if remediation_raises is not None:
                raise remediation_raises
            return remediation or RemediationRecord(RemediationOutcome.APPLIED, "done")

    return _Check()


def make_runner(
    checks: list[Check], system: FakeSystem, config: Config | None = None
) -> AuditRunner:
    return AuditRunner(CheckRegistry(checks), system, config or Config(), agent_version="test")


class TestErrorIsolation:
    def test_a_raising_check_becomes_error_not_a_crash(self, fake_system: FakeSystem) -> None:
        runner = make_runner([build_check("boom", raises=RuntimeError("kaboom"))], fake_system)
        report = runner.run()
        assert report.results[0].status is Status.ERROR
        assert "RuntimeError" in report.results[0].detail

    def test_one_broken_check_does_not_stop_the_others(self, fake_system: FakeSystem) -> None:
        """A partially-completed security audit is worse than a reported error."""
        runner = make_runner(
            [
                build_check("a", Finding.passed("ok")),
                build_check("boom", raises=ValueError("bad")),
                build_check("c", Finding.failed("nope")),
            ],
            fake_system,
        )
        report = runner.run()
        assert len(report.results) == 3
        assert report.counts() == {"pass": 1, "fail": 1, "skip": 0, "error": 1}

    def test_keyboard_interrupt_is_not_swallowed(self, fake_system: FakeSystem) -> None:
        """BaseException must propagate so Ctrl-C actually stops the run."""
        runner = make_runner([build_check("x", raises=KeyboardInterrupt())], fake_system)
        with pytest.raises(KeyboardInterrupt):
            runner.run()


class TestRemediationGating:
    def test_passing_checks_are_never_remediated(self, fake_system: FakeSystem) -> None:
        check = build_check("a", Finding.passed("ok"), remediable=True)
        report = make_runner([check], fake_system).run(remediate=True)
        assert report.results[0].remediation is None

    def test_non_remediable_check_reports_unsupported(self, fake_system: FakeSystem) -> None:
        check = build_check("a", Finding.failed("bad"), remediable=False)
        report = make_runner([check], fake_system).run(remediate=True)
        assert report.results[0].remediation is not None
        assert report.results[0].remediation.outcome is RemediationOutcome.UNSUPPORTED

    def test_risky_remediation_blocked_by_default(self, fake_system: FakeSystem) -> None:
        check = build_check("a", Finding.failed("bad"), remediable=True, risky=True)
        report = make_runner([check], fake_system).run(remediate=True)
        assert report.results[0].remediation.outcome is RemediationOutcome.SKIPPED
        assert "--allow-risky" in report.results[0].remediation.detail

    def test_risky_remediation_allowed_when_configured(self, fake_system: FakeSystem) -> None:
        config = Config(remediation=RemediationConfig(allow_risky=True))
        check = build_check("a", Finding.failed("bad"), remediable=True, risky=True)
        report = make_runner([check], fake_system, config).run(remediate=True)
        assert report.results[0].remediation.outcome is RemediationOutcome.APPLIED

    def test_remediation_requires_root(self) -> None:
        system = FakeSystem(root=False)
        check = build_check("a", Finding.failed("bad"), remediable=True)
        report = make_runner([check], system).run(remediate=True)
        assert report.results[0].remediation.outcome is RemediationOutcome.SKIPPED
        assert "root" in report.results[0].remediation.detail

    def test_dry_run_does_not_require_root(self) -> None:
        system = FakeSystem(root=False)
        check = build_check(
            "a",
            Finding.failed("bad"),
            remediable=True,
            remediation=RemediationRecord(RemediationOutcome.DRY_RUN, "would fix"),
        )
        report = make_runner([check], system).run(remediate=True, dry_run=True)
        assert report.results[0].remediation.outcome is RemediationOutcome.DRY_RUN

    def test_raising_remediation_is_contained(self, fake_system: FakeSystem) -> None:
        check = build_check(
            "a",
            Finding.failed("bad"),
            remediable=True,
            remediation_raises=OSError("disk full"),
        )
        report = make_runner([check], fake_system).run(remediate=True)
        assert report.results[0].remediation.outcome is RemediationOutcome.FAILED


class TestReAudit:
    def test_report_reflects_state_after_successful_remediation(
        self, fake_system: FakeSystem
    ) -> None:
        """Without the re-audit, a fixed control would still be reported failing."""
        check = build_check(
            "a",
            Finding.failed("bad"),
            remediable=True,
            remediation=RemediationRecord(RemediationOutcome.APPLIED, "fixed it"),
        )
        report = make_runner([check], fake_system).run(remediate=True)
        assert report.results[0].status is Status.PASS
        assert report.results[0].remediation.outcome is RemediationOutcome.APPLIED

    def test_no_re_audit_after_a_dry_run(self, fake_system: FakeSystem) -> None:
        """Nothing changed, so the finding must still show as failing."""
        check = build_check(
            "a",
            Finding.failed("bad"),
            remediable=True,
            remediation=RemediationRecord(RemediationOutcome.DRY_RUN, "would fix"),
        )
        report = make_runner([check], fake_system).run(remediate=True, dry_run=True)
        assert report.results[0].status is Status.FAIL


class TestReportAssembly:
    def test_records_timing_and_metadata(self, fake_system: FakeSystem) -> None:
        report = make_runner([build_check("a")], fake_system).run()
        assert report.agent_version == "test"
        assert report.results[0].duration_ms >= 0.0
        assert report.finished_at >= report.started_at

    def test_dry_run_flag_propagates_to_the_report(self, fake_system: FakeSystem) -> None:
        report = make_runner([build_check("a")], fake_system).run(dry_run=True)
        assert report.to_dict()["dry_run"] is True

    def test_respects_selection_config(self, fake_system: FakeSystem) -> None:
        config = Config(audit=AuditConfig(min_severity=Severity.CRITICAL))
        runner = make_runner(
            [
                build_check("low", severity=Severity.LOW),
                build_check("crit", severity=Severity.CRITICAL),
            ],
            fake_system,
            config,
        )
        report = runner.run()
        assert [r.check_id for r in report.results] == ["crit"]


class TestExitCodes:
    def test_clean_report_is_zero(self) -> None:
        report = make_report((Status.PASS, Severity.CRITICAL))
        assert determine_exit_code(report, Severity.HIGH) == EXIT_OK

    def test_finding_at_threshold_is_one(self) -> None:
        report = make_report((Status.FAIL, Severity.HIGH))
        assert determine_exit_code(report, Severity.HIGH) == EXIT_FINDINGS

    def test_finding_below_threshold_is_zero(self) -> None:
        report = make_report((Status.FAIL, Severity.LOW))
        assert determine_exit_code(report, Severity.HIGH) == EXIT_OK

    def test_error_outranks_findings(self) -> None:
        """A broken check means posture is unknown, not merely non-compliant."""
        report = make_report((Status.FAIL, Severity.CRITICAL), (Status.ERROR, Severity.LOW))
        assert determine_exit_code(report, Severity.HIGH) == EXIT_ERROR

    def test_error_alone_is_two(self) -> None:
        report = make_report((Status.ERROR, Severity.LOW))
        assert determine_exit_code(report, Severity.CRITICAL) == EXIT_ERROR
