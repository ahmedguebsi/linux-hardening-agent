"""Prometheus exposition rendering and report-to-metric translation."""

from __future__ import annotations

import math

import pytest

from hardening_agent.metrics import (
    MetricRegistry,
    build_report_metrics,
    render_report_metrics,
)
from hardening_agent.models import Severity, Status
from tests.test_models import make_report


class TestExpositionFormat:
    def test_help_and_type_lines_precede_samples(self) -> None:
        registry = MetricRegistry()
        registry.gauge("test_metric", "A test metric.").add(42)
        lines = registry.render().strip().splitlines()
        assert lines[0] == "# HELP test_metric A test metric."
        assert lines[1] == "# TYPE test_metric gauge"
        assert lines[2] == "test_metric 42"

    def test_labels_are_sorted_for_byte_stability(self) -> None:
        """Stable output keeps the textfile diffable across runs."""
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1, zebra="z", alpha="a", middle="m")
        assert 'm{alpha="a",middle="m",zebra="z"} 1' in registry.render()

    def test_no_braces_when_unlabelled(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1)
        assert "m 1" in registry.render()
        assert "{}" not in registry.render()

    def test_output_always_ends_with_newline(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1)
        assert registry.render().endswith("\n")

    def test_empty_registry_renders_a_newline(self) -> None:
        assert MetricRegistry().render() == "\n"

    def test_metric_without_samples_is_omitted(self) -> None:
        registry = MetricRegistry()
        registry.gauge("unused", "h")
        assert "unused" not in registry.render()

    def test_counter_type_is_declared(self) -> None:
        registry = MetricRegistry()
        registry.counter("c_total", "h").add(5)
        assert "# TYPE c_total counter" in registry.render()


class TestEscaping:
    def test_label_value_quotes_are_escaped(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1, title='He said "hi"')
        assert r'title="He said \"hi\""' in registry.render()

    def test_label_value_backslashes_are_escaped(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1, path=r"C:\temp")
        assert r'path="C:\\temp"' in registry.render()

    def test_label_value_newlines_are_escaped(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1, detail="line1\nline2")
        rendered = registry.render()
        assert r"line1\nline2" in rendered
        # A raw newline inside a label would produce an unparseable payload.
        assert len([ln for ln in rendered.splitlines() if ln.startswith("m{")]) == 1

    def test_help_text_newlines_are_escaped(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "first\nsecond").add(1)
        assert "# HELP m first\\nsecond" in registry.render()

    def test_check_titles_with_slashes_render_safely(self) -> None:
        """Real titles contain '/etc/shadow ...' -- must not break parsing."""
        registry = MetricRegistry()
        registry.gauge("m", "h").add(1, title="/etc/shadow is not readable")
        assert 'title="/etc/shadow is not readable"' in registry.render()


class TestValueRendering:
    def test_nan_uses_the_prometheus_token(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(float("nan"))
        assert "m NaN" in registry.render()

    @pytest.mark.parametrize("value,expected", [(math.inf, "+Inf"), (-math.inf, "-Inf")])
    def test_infinities(self, value: float, expected: str) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(value)
        assert f"m {expected}" in registry.render()

    def test_integers_render_without_decimal_point(self) -> None:
        registry = MetricRegistry()
        registry.gauge("m", "h").add(42)
        assert "m 42\n" in registry.render()


class TestRegistryBehaviour:
    def test_same_name_returns_the_same_family(self) -> None:
        registry = MetricRegistry()
        first = registry.gauge("m", "h")
        second = registry.gauge("m", "h")
        assert first is second
        assert len(registry) == 1

    def test_type_conflict_is_rejected(self) -> None:
        """A name that is both counter and gauge is unparseable by Prometheus."""
        registry = MetricRegistry()
        registry.gauge("m", "h")
        with pytest.raises(ValueError, match="already registered as gauge"):
            registry.counter("m", "h")

    def test_merge_combines_samples(self) -> None:
        first = MetricRegistry()
        first.gauge("a", "h").add(1)
        second = MetricRegistry()
        second.gauge("b", "h").add(2)
        first.merge(second)
        rendered = first.render()
        assert "a 1" in rendered
        assert "b 2" in rendered

    def test_merge_same_family_keeps_both_samples(self) -> None:
        first = MetricRegistry()
        first.gauge("m", "h").add(1, host="a")
        second = MetricRegistry()
        second.gauge("m", "h").add(2, host="b")
        first.merge(second)
        rendered = first.render()
        assert rendered.count("# TYPE m gauge") == 1
        assert 'm{host="a"} 1' in rendered
        assert 'm{host="b"} 2' in rendered


class TestReportMetrics:
    def test_status_encoded_as_numeric_gauge(self) -> None:
        """Status as a label value would leave stale series after a state change."""
        report = make_report(
            (Status.PASS, Severity.HIGH),
            (Status.FAIL, Severity.CRITICAL),
            (Status.SKIP, Severity.LOW),
            (Status.ERROR, Severity.MEDIUM),
        )
        rendered = build_report_metrics(report).render()

        def series(index: int, severity: str, value: int) -> str:
            return (
                f'hardening_agent_check_status{{check_id="check_{index}",'
                f'severity="{severity}",title="Test check"}} {value}'
            )

        # pass=1, fail=0, skip=2, error=3
        assert series(0, "high", 1) in rendered
        assert series(1, "critical", 0) in rendered
        assert series(2, "low", 2) in rendered
        assert series(3, "medium", 3) in rendered

    def test_no_status_label_is_emitted(self) -> None:
        rendered = build_report_metrics(make_report((Status.FAIL, Severity.HIGH))).render()
        assert "hardening_agent_check_status{status=" not in rendered

    def test_failed_by_severity_covers_every_level(self) -> None:
        """Zero-valued series must be present so alerts do not go stale-silent."""
        report = make_report((Status.FAIL, Severity.HIGH))
        rendered = build_report_metrics(report).render()
        for severity in ("low", "medium", "high", "critical"):
            assert f'hardening_agent_failed_checks_by_severity{{severity="{severity}"}}' in rendered
        assert 'hardening_agent_failed_checks_by_severity{severity="high"} 1' in rendered
        assert 'hardening_agent_failed_checks_by_severity{severity="low"} 0' in rendered

    def test_compliance_score_exported(self) -> None:
        report = make_report((Status.PASS, Severity.HIGH), (Status.FAIL, Severity.HIGH))
        assert "hardening_agent_compliance_score 50.0" in build_report_metrics(report).render()

    def test_host_info_is_a_constant_one_with_labels(self) -> None:
        rendered = build_report_metrics(make_report((Status.PASS, Severity.LOW))).render()
        assert 'hostname="h"' in rendered
        assert 'os_version="24.04"' in rendered
        assert rendered.count("hardening_agent_host_info{") == 1
        assert rendered.strip().endswith("} 1")

    def test_last_run_timestamp_exported_for_staleness_alerts(self) -> None:
        report = make_report((Status.PASS, Severity.LOW))
        assert (
            "hardening_agent_last_run_timestamp_seconds 1002.5"
            in build_report_metrics(report).render()
        )

    def test_counts_by_status_exported(self) -> None:
        report = make_report((Status.PASS, Severity.LOW), (Status.FAIL, Severity.LOW))
        rendered = build_report_metrics(report).render()
        assert 'hardening_agent_checks_total{status="pass"} 1' in rendered
        assert 'hardening_agent_checks_total{status="fail"} 1' in rendered

    def test_render_helper_merges_extra_registries(self) -> None:
        extra = MetricRegistry()
        extra.gauge("custom_metric", "h").add(7)
        rendered = render_report_metrics(make_report((Status.PASS, Severity.LOW)), {"host": extra})
        assert "custom_metric 7" in rendered
        assert "hardening_agent_compliance_score" in rendered

    def test_output_is_parseable_line_by_line(self) -> None:
        """Every non-comment line must be `name{labels} value`."""
        report = make_report((Status.FAIL, Severity.CRITICAL), (Status.PASS, Severity.LOW))
        for line in build_report_metrics(report).render().strip().splitlines():
            if line.startswith("#"):
                assert line.startswith(("# HELP ", "# TYPE "))
                continue
            name, _, value = line.rpartition(" ")
            assert name, f"no metric name in {line!r}"
            float(value)  # raises if the value is not numeric
