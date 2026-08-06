"""A minimal Prometheus exposition-format implementation.

Written by hand rather than pulling in ``prometheus_client`` because this agent
runs as root on production hosts and ships with zero runtime dependencies. The
exposition format is a stable, simple text protocol; implementing the subset we
need is ~100 lines and removes a supply-chain dependency from the root context.

Format reference: https://prometheus.io/docs/instrumenting/exposition_formats/
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from .models import Report, Severity, Status

MetricValue = int | float


@dataclass(frozen=True, slots=True)
class Sample:
    labels: tuple[tuple[str, str], ...]
    value: MetricValue


@dataclass(slots=True)
class Metric:
    """A single metric family: name, type, help text, and its samples."""

    name: str
    help_text: str
    metric_type: str = "gauge"
    samples: list[Sample] = field(default_factory=list)

    def add(self, value: MetricValue, **labels: str) -> None:
        # Sorted label keys keep output byte-stable across runs, which makes the
        # textfile diffable and avoids spurious file writes.
        normalised = tuple(sorted((str(k), str(v)) for k, v in labels.items()))
        self.samples.append(Sample(normalised, value))

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {_escape_help(self.help_text)}",
            f"# TYPE {self.name} {self.metric_type}",
        ]
        for sample in self.samples:
            lines.append(
                f"{self.name}{_render_labels(sample.labels)} {_render_value(sample.value)}"
            )
        return "\n".join(lines)


class MetricRegistry:
    """Ordered collection of metric families."""

    def __init__(self) -> None:
        self._metrics: dict[str, Metric] = {}

    def gauge(self, name: str, help_text: str) -> Metric:
        return self._metric(name, help_text, "gauge")

    def counter(self, name: str, help_text: str) -> Metric:
        return self._metric(name, help_text, "counter")

    def _metric(self, name: str, help_text: str, metric_type: str) -> Metric:
        existing = self._metrics.get(name)
        if existing is not None:
            if existing.metric_type != metric_type:
                raise ValueError(
                    f"metric {name!r} already registered as {existing.metric_type}, "
                    f"cannot redefine as {metric_type}"
                )
            return existing
        metric = Metric(name=name, help_text=help_text, metric_type=metric_type)
        self._metrics[name] = metric
        return metric

    def __len__(self) -> int:
        return len(self._metrics)

    def __iter__(self) -> Iterator[Metric]:
        return iter(self._metrics.values())

    def merge(self, other: MetricRegistry) -> None:
        """Absorb another registry's samples into this one.

        Families with the same name are combined; a type conflict raises, which
        is what we want -- silently mixing a counter and a gauge under one name
        produces a metric Prometheus cannot interpret.
        """
        for metric in other:
            target = self._metric(metric.name, metric.help_text, metric.metric_type)
            if target is not metric:
                target.samples.extend(metric.samples)

    def render(self) -> str:
        """Render the full exposition payload. Always ends with a newline."""
        blocks = [metric.render() for metric in self._metrics.values() if metric.samples]
        return "\n".join(blocks) + "\n" if blocks else "\n"


def _escape_help(text: str) -> str:
    """HELP text escapes backslash and newline only (per the spec)."""
    return text.replace("\\", r"\\").replace("\n", r"\n")


def _escape_label_value(value: str) -> str:
    """Label values additionally escape the double quote."""
    return value.replace("\\", r"\\").replace('"', r"\"").replace("\n", r"\n")


def _render_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{key}="{_escape_label_value(value)}"' for key, value in labels)
    return "{" + rendered + "}"


def _render_value(value: MetricValue) -> str:
    """Render a value using Prometheus' special tokens for non-finite floats."""
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "+Inf" if value > 0 else "-Inf"
        # repr() keeps full float precision without scientific-notation surprises
        # for the magnitudes this agent produces.
        return repr(value)
    return str(value)


# ---------------------------------------------------------------------------
# Report -> metrics
# ---------------------------------------------------------------------------
NAMESPACE = "hardening_agent"


def build_report_metrics(report: Report, registry: MetricRegistry | None = None) -> MetricRegistry:
    """Translate an audit report into metrics.

    Design note: check status is exposed as a numeric gauge per check rather than
    as a label like ``status="fail"``. Using the status as a label value would
    create a new time series on every state change and leave stale series behind
    that keep reporting the old state forever.
    """
    registry = registry or MetricRegistry()

    status_metric = registry.gauge(
        f"{NAMESPACE}_check_status",
        "Check outcome: 1=pass, 0=fail, 2=skip, 3=error.",
    )
    duration_metric = registry.gauge(
        f"{NAMESPACE}_check_duration_seconds", "Wall-clock time to execute each check."
    )
    for result in report.results:
        labels = {
            "check_id": result.check_id,
            "severity": result.severity.value,
            "title": result.metadata.title,
        }
        status_metric.add(_status_value(result.status), **labels)
        duration_metric.add(
            round(result.duration_ms / 1000.0, 6),
            check_id=result.check_id,
        )

    counts = report.counts()
    total_metric = registry.gauge(f"{NAMESPACE}_checks_total", "Number of checks by outcome.")
    for status_name, count in sorted(counts.items()):
        total_metric.add(count, status=status_name)

    failed_by_severity = registry.gauge(
        f"{NAMESPACE}_failed_checks_by_severity",
        "Number of failing checks grouped by severity.",
    )
    tally = {severity.value: 0 for severity in Severity}
    for result in report.failures():
        tally[result.severity.value] += 1
    for severity_name, count in sorted(tally.items()):
        failed_by_severity.add(count, severity=severity_name)

    registry.gauge(
        f"{NAMESPACE}_compliance_score",
        "Percentage of applicable checks that passed (0-100).",
    ).add(report.score())

    registry.gauge(
        f"{NAMESPACE}_last_run_timestamp_seconds",
        "Unix timestamp of the last completed audit.",
    ).add(round(report.finished_at, 3))

    registry.gauge(
        f"{NAMESPACE}_run_duration_seconds", "Wall-clock duration of the last audit."
    ).add(round(report.duration_ms / 1000.0, 6))

    # An "info" metric: constant 1 with descriptive labels. The standard way to
    # attach host metadata without creating a series per changing value.
    registry.gauge(f"{NAMESPACE}_host_info", "Host metadata; value is always 1.").add(
        1,
        hostname=report.host.hostname,
        os_name=report.host.os_name,
        os_version=report.host.os_version,
        kernel=report.host.kernel,
        architecture=report.host.architecture,
        virtualization=report.host.virtualization,
        agent_version=report.agent_version,
        profile=report.profile,
    )
    return registry


def _status_value(status: Status) -> int:
    return {Status.PASS: 1, Status.FAIL: 0, Status.SKIP: 2, Status.ERROR: 3}[status]


def render_report_metrics(report: Report, extra: Mapping[str, MetricRegistry] | None = None) -> str:
    """Render report metrics, optionally merged with additional registries."""
    registry = build_report_metrics(report)
    for other in (extra or {}).values():
        registry.merge(other)
    return registry.render()
