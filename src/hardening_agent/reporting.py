"""Report rendering.

Three output formats, each with a distinct consumer:

``text``
    A human at a terminal. Colour is applied only when stdout is a TTY, so
    piping into a file or a log never embeds escape codes.
``json``
    Machines: CI gates, SIEM ingestion, ``jq``. Schema-versioned so downstream
    parsers can detect breaking changes.
``sarif``
    GitHub code scanning. Lets findings appear in the Security tab of the repo
    that owns the infrastructure code, which is where engineers already look.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, TextIO

from .models import Report, Severity, Status

_RESET = "\033[0m"
_COLOURS = {
    Status.PASS: "\033[32m",
    Status.FAIL: "\033[31m",
    Status.SKIP: "\033[90m",
    Status.ERROR: "\033[35m",
}
_SEVERITY_COLOURS = {
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m",
    Severity.CRITICAL: "\033[1;31m",
}


def supports_colour(stream: TextIO) -> bool:
    """Colour only for interactive terminals that have not opted out.

    Honours the NO_COLOR convention (https://no-color.org) because a security
    tool's output frequently ends up in tickets and pipelines.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render_json(report: Report, *, indent: int | None = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False, default=str)


def render_text(report: Report, *, colour: bool | None = None, verbose: bool = False) -> str:
    """Human-readable report."""
    use_colour = supports_colour(sys.stdout) if colour is None else colour

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if use_colour else text

    host = report.host
    counts = report.counts()
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(f" Linux Hardening Report  ({report.agent_version}, profile: {report.profile})")
    lines.append("=" * 78)
    lines.append(f" Host        : {host.hostname}  [{host.os_name} {host.os_version}]")
    lines.append(f" Kernel      : {host.kernel} ({host.architecture}, {host.virtualization})")
    lines.append(f" Duration    : {report.duration_ms:.0f} ms")
    if report.dry_run:
        lines.append(" Mode        : DRY RUN (no changes were made)")
    lines.append("")

    # Failures first: the reader's attention is finite and this is the payload.
    failures = sorted(report.failures(), key=lambda r: (-r.severity.rank, r.check_id))
    if failures:
        lines.append(
            paint(f" FINDINGS ({len(failures)})", "\033[1m")
            if use_colour
            else f" FINDINGS ({len(failures)})"
        )
        lines.append("-" * 78)
        for result in failures:
            marker = paint(
                f"[{result.severity.value.upper():^8}]", _SEVERITY_COLOURS[result.severity]
            )
            lines.append(f" {marker} {result.check_id}")
            lines.append(f"            {result.metadata.title}")
            lines.append(f"            -> {result.detail}")
            if result.remediation is not None:
                lines.append(
                    f"            remediation: {result.remediation.outcome.value} "
                    f"- {result.remediation.detail}"
                )
            if verbose:
                lines.append(f"            why: {result.metadata.rationale}")
                if result.evidence:
                    lines.append(
                        f"            evidence: {json.dumps(dict(result.evidence), default=str)}"
                    )
            lines.append("")

    errors = report.errors()
    if errors:
        lines.append(" ERRORS (check did not complete - posture unknown)")
        lines.append("-" * 78)
        for result in errors:
            lines.append(
                f" [{result.severity.value.upper():^8}] {result.check_id}: {result.detail}"
            )
        lines.append("")

    if verbose:
        passed = [r for r in report.results if r.status is Status.PASS]
        skipped = [r for r in report.results if r.status is Status.SKIP]
        if passed:
            lines.append(f" PASSED ({len(passed)})")
            lines.append("-" * 78)
            for result in sorted(passed, key=lambda r: r.check_id):
                lines.append(
                    f"   {paint('PASS', _COLOURS[Status.PASS])}  {result.check_id}: {result.detail}"
                )
            lines.append("")
        if skipped:
            lines.append(f" SKIPPED ({len(skipped)})")
            lines.append("-" * 78)
            for result in sorted(skipped, key=lambda r: r.check_id):
                lines.append(
                    f"   {paint('SKIP', _COLOURS[Status.SKIP])}  {result.check_id}: {result.detail}"
                )
            lines.append("")

    lines.append("-" * 78)
    summary = (
        f" pass={counts['pass']}  fail={counts['fail']}  "
        f"skip={counts['skip']}  error={counts['error']}"
    )
    lines.append(summary)
    score = report.score()
    score_colour = "\033[32m" if score >= 90 else "\033[33m" if score >= 70 else "\033[31m"
    lines.append(
        f" Compliance score: {paint(f'{score:.1f}%', score_colour)} (of applicable checks)"
    )
    lines.append("=" * 78)
    return "\n".join(lines) + "\n"


def render_sarif(report: Report) -> str:
    """SARIF 2.1.0 for GitHub code scanning ingestion."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for result in report.results:
        meta = result.metadata
        rules.append(
            {
                "id": meta.check_id,
                "name": "".join(part.capitalize() for part in meta.check_id.split("_")),
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.description},
                "help": {"text": meta.rationale},
                "properties": {
                    "tags": sorted(meta.tags),
                    "security-severity": _security_severity(meta.severity),
                },
                "defaultConfiguration": {"level": _sarif_level(meta.severity)},
            }
        )
        if result.status is not Status.FAIL:
            continue
        results.append(
            {
                "ruleId": meta.check_id,
                "level": _sarif_level(meta.severity),
                "message": {"text": f"{meta.title}: {result.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(result.evidence.get("path", report.host.hostname))
                            }
                        }
                    }
                ],
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hardening-agent",
                        "version": report.agent_version,
                        "informationUri": "https://github.com/example/linux-hardening-agent",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.LOW: "note",
        Severity.MEDIUM: "warning",
        Severity.HIGH: "error",
        Severity.CRITICAL: "error",
    }[severity]


def _security_severity(severity: Severity) -> str:
    """GitHub renders this as a CVSS-like 0-10 score."""
    return {
        Severity.LOW: "3.0",
        Severity.MEDIUM: "5.5",
        Severity.HIGH: "7.5",
        Severity.CRITICAL: "9.5",
    }[severity]


def render(report: Report, output_format: str, *, verbose: bool = False) -> str:
    match output_format:
        case "json":
            return render_json(report)
        case "text":
            return render_text(report, verbose=verbose)
        case "sarif":
            return render_sarif(report)
        case _:
            raise ValueError(f"unsupported format: {output_format!r}")
