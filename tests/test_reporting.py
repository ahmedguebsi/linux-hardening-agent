"""Report rendering in text, JSON and SARIF."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from hardening_agent.models import Severity, Status
from hardening_agent.reporting import (
    render,
    render_json,
    render_sarif,
    render_text,
    supports_colour,
)
from tests.test_models import make_report


class TestJson:
    def test_is_valid_json(self) -> None:
        payload = json.loads(render_json(make_report((Status.FAIL, Severity.HIGH))))
        assert payload["counts"]["fail"] == 1

    def test_includes_metadata_and_evidence_keys(self) -> None:
        payload = json.loads(render_json(make_report((Status.FAIL, Severity.HIGH))))
        result = payload["results"][0]
        for key in ("check_id", "severity", "status", "detail", "rationale", "evidence"):
            assert key in result

    def test_compact_mode(self) -> None:
        compact = render_json(make_report((Status.PASS, Severity.LOW)), indent=None)
        assert "\n" not in compact.strip()


class TestText:
    def test_findings_section_lists_failures(self) -> None:
        output = render_text(make_report((Status.FAIL, Severity.CRITICAL)), colour=False)
        assert "FINDINGS (1)" in output
        assert "CRITICAL" in output
        assert "check_0" in output

    def test_errors_are_a_separate_section(self) -> None:
        """Errors mean unknown posture and must not read as findings."""
        output = render_text(make_report((Status.ERROR, Severity.HIGH)), colour=False)
        assert "posture unknown" in output
        assert "FINDINGS" not in output

    def test_passes_hidden_unless_verbose(self) -> None:
        report = make_report((Status.PASS, Severity.LOW))
        assert "PASSED" not in render_text(report, colour=False)
        assert "PASSED" in render_text(report, colour=False, verbose=True)

    def test_verbose_includes_rationale_for_failures(self) -> None:
        output = render_text(make_report((Status.FAIL, Severity.HIGH)), colour=False, verbose=True)
        assert "why:" in output

    def test_findings_ordered_by_severity(self) -> None:
        report = make_report(
            (Status.FAIL, Severity.LOW),
            (Status.FAIL, Severity.CRITICAL),
            (Status.FAIL, Severity.MEDIUM),
        )
        output = render_text(report, colour=False)
        assert output.index("CRITICAL") < output.index("MEDIUM") < output.index("LOW")

    def test_no_escape_codes_when_colour_disabled(self) -> None:
        """Reports end up in tickets and log files; escape codes are noise there."""
        output = render_text(make_report((Status.FAIL, Severity.HIGH)), colour=False)
        assert "\033[" not in output

    def test_colour_emits_escape_codes(self) -> None:
        output = render_text(make_report((Status.FAIL, Severity.HIGH)), colour=True)
        assert "\033[" in output

    def test_summary_line_and_score(self) -> None:
        report = make_report((Status.PASS, Severity.LOW), (Status.FAIL, Severity.LOW))
        output = render_text(report, colour=False)
        assert "pass=1" in output
        assert "fail=1" in output
        assert "50.0%" in output

    def test_dry_run_is_announced(self) -> None:
        report = replace(make_report((Status.FAIL, Severity.HIGH)), dry_run=True)
        assert "DRY RUN" in render_text(report, colour=False)


class TestColourDetection:
    def test_no_color_env_disables(self, monkeypatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")

        class TTY:
            def isatty(self) -> bool:
                return True

        assert supports_colour(TTY()) is False

    def test_dumb_terminal_disables(self, monkeypatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")

        class TTY:
            def isatty(self) -> bool:
                return True

        assert supports_colour(TTY()) is False

    def test_non_tty_disables(self, monkeypatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)

        class Pipe:
            def isatty(self) -> bool:
                return False

        assert supports_colour(Pipe()) is False


class TestSarif:
    def test_is_valid_sarif_2_1_0(self) -> None:
        document = json.loads(render_sarif(make_report((Status.FAIL, Severity.HIGH))))
        assert document["version"] == "2.1.0"
        assert document["runs"][0]["tool"]["driver"]["name"] == "hardening-agent"

    def test_only_failures_become_results(self) -> None:
        """Passing controls are rules, not code-scanning alerts."""
        report = make_report((Status.PASS, Severity.HIGH), (Status.FAIL, Severity.HIGH))
        document = json.loads(render_sarif(report))
        assert len(document["runs"][0]["results"]) == 1
        assert len(document["runs"][0]["tool"]["driver"]["rules"]) == 2

    def test_severity_maps_to_sarif_levels(self) -> None:
        report = make_report(
            (Status.FAIL, Severity.LOW),
            (Status.FAIL, Severity.MEDIUM),
            (Status.FAIL, Severity.CRITICAL),
        )
        levels = [r["level"] for r in json.loads(render_sarif(report))["runs"][0]["results"]]
        assert levels == ["note", "warning", "error"]

    def test_security_severity_property_present(self) -> None:
        """GitHub renders this as the CVSS-like score in the Security tab."""
        document = json.loads(render_sarif(make_report((Status.FAIL, Severity.CRITICAL))))
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.5"


class TestDispatch:
    def test_each_format_dispatches(self) -> None:
        report = make_report((Status.FAIL, Severity.HIGH))
        assert "FINDINGS" in render(report, "text")
        assert json.loads(render(report, "json"))
        assert json.loads(render(report, "sarif"))

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported format"):
            render(make_report(), "xml")
