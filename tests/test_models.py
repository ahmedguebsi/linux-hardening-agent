"""Domain model semantics."""

from __future__ import annotations

import json

import pytest

from hardening_agent.models import (
    CheckMetadata,
    CheckResult,
    Finding,
    HostInfo,
    Report,
    Severity,
    Status,
)


def make_metadata(
    check_id: str = "test_check", severity: Severity = Severity.HIGH
) -> CheckMetadata:
    return CheckMetadata(
        check_id=check_id,
        title="Test check",
        description="A check used in tests.",
        severity=severity,
        rationale="Because.",
    )


def make_report(*statuses: tuple[Status, Severity]) -> Report:
    results = tuple(
        CheckResult(
            metadata=make_metadata(f"check_{index}", severity),
            status=status,
            detail="detail",
        )
        for index, (status, severity) in enumerate(statuses)
    )
    return Report(
        host=HostInfo("h", "Ubuntu", "24.04", "6.8.0", "x86_64"),
        results=results,
        started_at=1000.0,
        finished_at=1002.5,
        agent_version="1.0.0",
        profile="baseline",
    )


class TestSeverity:
    def test_ordering(self) -> None:
        assert (
            Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank
        )

    def test_parse_is_case_and_space_insensitive(self) -> None:
        assert Severity.parse("  HIGH ") is Severity.HIGH

    def test_parse_rejects_unknown(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("catastrophic")

    def test_serialises_as_plain_string(self) -> None:
        assert json.dumps({"s": Severity.HIGH}) == '{"s": "high"}'


class TestStatus:
    def test_fail_and_error_are_actionable(self) -> None:
        assert Status.FAIL.is_actionable
        assert Status.ERROR.is_actionable

    def test_pass_and_skip_are_not(self) -> None:
        assert not Status.PASS.is_actionable
        assert not Status.SKIP.is_actionable


class TestCheckMetadata:
    def test_empty_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            CheckMetadata("", "t", "d", Severity.LOW, "r")

    def test_invalid_characters_rejected(self) -> None:
        """ids become Prometheus label values and JSON keys; keep them clean."""
        with pytest.raises(ValueError, match="alphanumeric"):
            CheckMetadata("bad id!", "t", "d", Severity.LOW, "r")

    def test_underscores_and_hyphens_allowed(self) -> None:
        CheckMetadata("ssh_root-login_1", "t", "d", Severity.LOW, "r")

    def test_is_immutable(self) -> None:
        meta = make_metadata()
        with pytest.raises(AttributeError):
            meta.check_id = "changed"  # type: ignore[misc]


class TestFinding:
    def test_constructors_set_status(self) -> None:
        assert Finding.passed("ok").status is Status.PASS
        assert Finding.failed("no").status is Status.FAIL
        assert Finding.skipped("n/a").status is Status.SKIP
        assert Finding.errored("boom").status is Status.ERROR

    def test_evidence_captured_from_kwargs(self) -> None:
        finding = Finding.failed("bad", path="/etc/x", mode="0777")
        assert finding.evidence == {"path": "/etc/x", "mode": "0777"}


class TestReportScoring:
    def test_all_pass_is_100(self) -> None:
        report = make_report((Status.PASS, Severity.HIGH), (Status.PASS, Severity.LOW))
        assert report.score() == 100.0

    def test_half_failing_is_50(self) -> None:
        report = make_report((Status.PASS, Severity.HIGH), (Status.FAIL, Severity.LOW))
        assert report.score() == 50.0

    def test_skipped_checks_are_excluded_not_counted_as_passes(self) -> None:
        """Otherwise a host where nothing applies would score misleadingly well."""
        report = make_report(
            (Status.PASS, Severity.HIGH),
            (Status.FAIL, Severity.LOW),
            (Status.SKIP, Severity.HIGH),
            (Status.SKIP, Severity.HIGH),
        )
        assert report.score() == 50.0

    def test_errors_are_excluded_from_the_score(self) -> None:
        report = make_report((Status.PASS, Severity.HIGH), (Status.ERROR, Severity.HIGH))
        assert report.score() == 100.0

    def test_no_applicable_checks_scores_100(self) -> None:
        assert make_report((Status.SKIP, Severity.HIGH)).score() == 100.0

    def test_empty_report_scores_100(self) -> None:
        assert make_report().score() == 100.0


class TestReportAggregation:
    def test_counts_every_status(self) -> None:
        report = make_report(
            (Status.PASS, Severity.LOW),
            (Status.PASS, Severity.LOW),
            (Status.FAIL, Severity.HIGH),
            (Status.SKIP, Severity.LOW),
            (Status.ERROR, Severity.LOW),
        )
        assert report.counts() == {"pass": 2, "fail": 1, "skip": 1, "error": 1}

    def test_worst_failed_severity_ignores_passing_checks(self) -> None:
        report = make_report(
            (Status.PASS, Severity.CRITICAL),
            (Status.FAIL, Severity.MEDIUM),
            (Status.FAIL, Severity.LOW),
        )
        assert report.worst_failed_severity() is Severity.MEDIUM

    def test_worst_failed_severity_none_when_clean(self) -> None:
        assert make_report((Status.PASS, Severity.CRITICAL)).worst_failed_severity() is None

    def test_duration_is_milliseconds(self) -> None:
        assert make_report().duration_ms == 2500.0


class TestSerialisation:
    def test_report_dict_is_json_serialisable(self) -> None:
        report = make_report((Status.FAIL, Severity.HIGH))
        json.dumps(report.to_dict())

    def test_schema_version_present(self) -> None:
        assert make_report().to_dict()["schema_version"] == "1.0"

    def test_timestamps_are_utc_iso(self) -> None:
        payload = make_report().to_dict()
        assert payload["started_at"].endswith("Z")
        assert "T" in payload["started_at"]
