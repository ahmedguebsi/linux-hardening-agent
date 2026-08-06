"""Command-line interface.

Subcommands:

``audit``        read-only assessment (the default posture)
``remediate``    apply fixes for failing checks; ``--dry-run`` shows the plan
``export``       run once and write the Prometheus textfile, then exit
``serve``        run the HTTP exporter until terminated
``list-checks``  print the catalogue
``config``       show effective configuration and where it came from

Exit codes are a stable contract (see :mod:`hardening_agent.runner`):
0 compliant, 1 findings at/above the threshold, 2 a check errored, 3 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TextIO

from . import __version__
from .config import Config, ConfigError, load_config
from .exporter import serve
from .logging_setup import configure_logging, get_logger
from .metrics import build_report_metrics
from .models import Severity
from .observability import collect_host_metrics, write_textfile
from .registry import CheckRegistry, UnknownCheckError
from .reporting import render
from .runner import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    AuditRunner,
    determine_exit_code,
)
from .system import LocalSystem

logger = get_logger("cli")

PROGRAM = "hardening-agent"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Linux hardening audit, remediation and observability agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  compliant (no findings at or above the fail threshold)\n"
            "  1  findings at or above the fail threshold\n"
            "  2  one or more checks errored; posture is unknown\n"
            "  3  usage or configuration error\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")

    # Global options are defined once and attached to each subparser so that
    # both `agent --config X audit` and `agent audit --config X` work.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", metavar="PATH", help="path to agent.toml")
    common.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="override logging.level",
    )
    common.add_argument("--log-format", choices=("json", "text"), help="override logging.format")
    common.add_argument(
        "--root",
        metavar="PATH",
        default="/",
        help="inspect a filesystem mounted elsewhere (e.g. /host in a container)",
    )

    selection = argparse.ArgumentParser(add_help=False)
    selection.add_argument(
        "--check",
        dest="include",
        action="append",
        metavar="ID",
        help="run only this check; repeatable",
    )
    selection.add_argument(
        "--exclude",
        action="append",
        metavar="ID",
        help="skip this check; repeatable",
    )
    selection.add_argument(
        "--tag", dest="tags", action="append", metavar="TAG", help="run checks with this tag"
    )
    selection.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        help="only run checks at or above this severity",
    )
    selection.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit 1 when a finding at or above this severity exists",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser(
        "audit", parents=[common, selection], help="run a read-only assessment"
    )
    audit.add_argument(
        "-f", "--format", choices=("text", "json", "sarif"), default="text", help="output format"
    )
    audit.add_argument("-o", "--output", metavar="PATH", help="write the report to a file")
    audit.add_argument(
        "-v", "--verbose", action="store_true", help="include passing checks and evidence"
    )
    audit.add_argument(
        "--write-textfile",
        action="store_true",
        help="also publish metrics to the configured textfile path",
    )

    remediate = subparsers.add_parser(
        "remediate", parents=[common, selection], help="apply fixes for failing checks"
    )
    remediate.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would change without touching the host",
    )
    remediate.add_argument(
        "--allow-risky",
        action="store_true",
        help="permit remediations that can sever access (firewall, SSH password auth)",
    )
    remediate.add_argument(
        "-f", "--format", choices=("text", "json", "sarif"), default="text", help="output format"
    )
    remediate.add_argument("-o", "--output", metavar="PATH", help="write the report to a file")
    remediate.add_argument("-v", "--verbose", action="store_true", help="verbose report")
    remediate.add_argument(
        "--yes",
        action="store_true",
        help="required for a non-dry-run remediation; confirms intent to modify the host",
    )

    export = subparsers.add_parser(
        "export", parents=[common, selection], help="run once and write the metrics textfile"
    )
    export.add_argument(
        "--stdout", action="store_true", help="print metrics instead of writing the textfile"
    )

    subparsers.add_parser(
        "serve", parents=[common, selection], help="run the HTTP metrics exporter"
    )

    list_checks = subparsers.add_parser(
        "list-checks", parents=[common, selection], help="print the check catalogue"
    )
    list_checks.add_argument(
        "-f", "--format", choices=("text", "json"), default="text", help="output format"
    )

    config_cmd = subparsers.add_parser(
        "config", parents=[common], help="show effective configuration"
    )
    config_cmd.add_argument(
        "-f", "--format", choices=("text", "json"), default="text", help="output format"
    )

    return parser


def apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    """Layer CLI flags on top of file and environment configuration."""
    audit = config.audit
    if getattr(args, "include", None):
        audit = replace(audit, include=tuple(args.include))
    if getattr(args, "exclude", None):
        audit = replace(audit, exclude=tuple(args.exclude))
    if getattr(args, "tags", None):
        audit = replace(audit, tags=tuple(args.tags))
    if getattr(args, "min_severity", None):
        audit = replace(audit, min_severity=Severity.parse(args.min_severity))
    if getattr(args, "fail_on", None):
        audit = replace(audit, fail_on_severity=Severity.parse(args.fail_on))

    logging_cfg = config.logging
    if getattr(args, "log_level", None):
        logging_cfg = replace(logging_cfg, level=args.log_level)
    if getattr(args, "log_format", None):
        logging_cfg = replace(logging_cfg, format=args.log_format)
    if getattr(args, "verbose", False):
        logging_cfg = replace(logging_cfg, include_evidence=True)

    remediation = config.remediation
    if getattr(args, "allow_risky", False):
        remediation = replace(remediation, allow_risky=True)

    return replace(config, audit=audit, logging=logging_cfg, remediation=remediation).validate()


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = stdout if stdout is not None else sys.stdout

    try:
        config = apply_overrides(load_config(args.config), args)
    except ConfigError as exc:
        print(f"{PROGRAM}: configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    configure_logging(config.logging)
    system = LocalSystem(root=args.root)
    registry = CheckRegistry.with_defaults()

    try:
        match args.command:
            case "audit":
                return _cmd_audit(args, config, system, registry, out)
            case "remediate":
                return _cmd_remediate(args, config, system, registry, out)
            case "export":
                return _cmd_export(args, config, system, registry, out)
            case "serve":
                return _cmd_serve(config, system, registry)
            case "list-checks":
                return _cmd_list_checks(args, config, registry, out)
            case "config":
                return _cmd_config(args, config, out)
            case _:  # pragma: no cover - argparse enforces the choices
                # parser.error is NoReturn: it prints usage and exits 2.
                parser.error(f"unknown command {args.command!r}")
    except UnknownCheckError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print(f"\n{PROGRAM}: interrupted", file=sys.stderr)
        return EXIT_ERROR


def _make_runner(config: Config, system: LocalSystem, registry: CheckRegistry) -> AuditRunner:
    return AuditRunner(registry, system, config, agent_version=__version__)


def _cmd_audit(
    args: argparse.Namespace,
    config: Config,
    system: LocalSystem,
    registry: CheckRegistry,
    out: TextIO,
) -> int:
    runner = _make_runner(config, system, registry)
    report = runner.run(remediate=False)
    rendered = render(report, args.format, verbose=args.verbose)
    _emit(rendered, args.output, out)

    if args.write_textfile and config.metrics.enabled:
        metric_registry = build_report_metrics(report)
        if config.metrics.host_metrics:
            metric_registry.merge(collect_host_metrics(system, config.metrics.monitored_mounts))
        try:
            write_textfile(config.textfile_path, metric_registry.render())
        except OSError as exc:
            print(f"{PROGRAM}: could not write textfile: {exc}", file=sys.stderr)
            return EXIT_ERROR

    return determine_exit_code(report, config.audit.fail_on_severity)


def _cmd_remediate(
    args: argparse.Namespace,
    config: Config,
    system: LocalSystem,
    registry: CheckRegistry,
    out: TextIO,
) -> int:
    # Guard rail: modifying a host must be an explicit, deliberate act. A typo'd
    # `remediate` that was meant to be `audit` should not reconfigure sshd.
    if not args.dry_run and not args.yes:
        print(
            f"{PROGRAM}: refusing to modify the host without --yes.\n"
            f"  preview changes first:  {PROGRAM} remediate --dry-run\n"
            f"  then apply them:        {PROGRAM} remediate --yes",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not args.dry_run and not system.is_root():
        print(f"{PROGRAM}: remediation requires root privileges", file=sys.stderr)
        return EXIT_USAGE

    runner = _make_runner(config, system, registry)
    report = runner.run(remediate=True, dry_run=args.dry_run)
    _emit(render(report, args.format, verbose=args.verbose), args.output, out)
    return determine_exit_code(report, config.audit.fail_on_severity)


def _cmd_export(
    args: argparse.Namespace,
    config: Config,
    system: LocalSystem,
    registry: CheckRegistry,
    out: TextIO,
) -> int:
    runner = _make_runner(config, system, registry)
    report = runner.run(remediate=False)
    metric_registry = build_report_metrics(report)
    if config.metrics.host_metrics:
        metric_registry.merge(collect_host_metrics(system, config.metrics.monitored_mounts))
    rendered = metric_registry.render()

    if args.stdout:
        out.write(rendered)
        return EXIT_OK
    try:
        write_textfile(config.textfile_path, rendered)
    except OSError as exc:
        print(f"{PROGRAM}: could not write textfile: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"wrote {config.textfile_path}", file=sys.stderr)
    return EXIT_OK


def _cmd_serve(config: Config, system: LocalSystem, registry: CheckRegistry) -> int:
    if not config.exporter.enabled:
        print(f"{PROGRAM}: exporter is disabled in configuration", file=sys.stderr)
        return EXIT_USAGE
    runner = _make_runner(config, system, registry)
    return serve(runner, config)


def _cmd_list_checks(
    args: argparse.Namespace, config: Config, registry: CheckRegistry, out: TextIO
) -> int:
    selected = registry.select(config.audit)
    if args.format == "json":
        out.write(json.dumps([c.metadata.to_dict() for c in selected], indent=2) + "\n")
        return EXIT_OK

    out.write(f"{len(selected)} check(s) selected of {len(registry)} available\n\n")
    out.write(f"{'SEVERITY':<10} {'ID':<42} REMEDIABLE  TITLE\n")
    out.write("-" * 110 + "\n")
    for check in selected:
        meta = check.metadata
        flag = "yes" if meta.remediable else "no"
        if meta.remediable and meta.risky_remediation:
            flag = "risky"
        out.write(f"{meta.severity.value:<10} {meta.check_id:<42} {flag:<11} {meta.title}\n")
    out.write("\nTags: " + ", ".join(registry.all_tags()) + "\n")
    return EXIT_OK


def _cmd_config(args: argparse.Namespace, config: Config, out: TextIO) -> int:
    payload = {
        "source_path": config.source_path or "<defaults>",
        "audit": {
            "profile": config.audit.profile,
            "include": list(config.audit.include),
            "exclude": list(config.audit.exclude),
            "tags": list(config.audit.tags),
            "min_severity": config.audit.min_severity.value,
            "fail_on_severity": config.audit.fail_on_severity.value,
            "check_timeout": config.audit.check_timeout,
        },
        "logging": {
            "level": config.logging.level,
            "format": config.logging.format,
            "file": config.logging.file,
            "include_evidence": config.logging.include_evidence,
        },
        "exporter": {
            "enabled": config.exporter.enabled,
            "host": config.exporter.host,
            "port": config.exporter.port,
            "refresh_interval": config.exporter.refresh_interval,
        },
        "metrics": {
            "enabled": config.metrics.enabled,
            "textfile_path": config.textfile_path,
            "host_metrics": config.metrics.host_metrics,
            "monitored_mounts": list(config.metrics.monitored_mounts),
        },
        "remediation": {
            "enabled": config.remediation.enabled,
            "allow_risky": config.remediation.allow_risky,
            "backup_dir": config.remediation.backup_dir,
            "keep_backups": config.remediation.keep_backups,
        },
    }
    if args.format == "json":
        out.write(json.dumps(payload, indent=2) + "\n")
        return EXIT_OK
    out.write(f"config source: {payload['source_path']}\n\n")
    for section, values in payload.items():
        if not isinstance(values, dict):
            continue
        out.write(f"[{section}]\n")
        for key, value in values.items():
            out.write(f"  {key} = {value}\n")
        out.write("\n")
    return EXIT_OK


def _emit(content: str, output_path: str | None, out: TextIO) -> None:
    if output_path:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        print(f"report written to {target}", file=sys.stderr)
    else:
        out.write(content)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
