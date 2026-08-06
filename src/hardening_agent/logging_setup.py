"""Structured logging configuration.

Two formats are supported:

``json``
    One JSON object per line. This is what runs in production: journald,
    Fluent Bit, Vector, and CloudWatch all ingest it without a parser plugin,
    and fields survive into the log backend as queryable attributes.

``text``
    Human-readable, used for interactive terminal runs.

Log records must never contain secrets. Checks put observed values in a
``Finding``'s evidence, and evidence is only logged when
``logging.include_evidence`` is explicitly enabled.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from pathlib import Path
from typing import Any

from .config import LoggingConfig

# Attributes present on every LogRecord; anything else is caller-supplied
# context and gets promoted to a top-level JSON field.
_RESERVED_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object."""

    def __init__(self, *, service: str = "hardening-agent") -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "service": self._service,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED_ATTRS or key.startswith("_"):
                continue
            payload[key] = _coerce(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """Compact single-line human format with contextual key=value pairs."""

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        self.default_time_format = "%H:%M:%S"
        self.default_msec_format = "%s.%03d"

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED_ATTRS and not key.startswith("_")
        }
        if extras:
            rendered = " ".join(f"{k}={_coerce(v)!r}" for k, v in sorted(extras.items()))
            base = f"{base} [{rendered}]"
        return base


def _coerce(value: Any) -> Any:
    """Keep JSON-native types, stringify everything else."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_coerce(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _coerce(v) for k, v in value.items()}
    return str(value)


def configure_logging(config: LoggingConfig, *, stream: Any = None) -> logging.Logger:
    """Install handlers on the package logger. Idempotent.

    Logs go to stderr so that stdout stays reserved for machine-readable report
    output -- ``hardening-agent audit --format json | jq`` must never be polluted
    by a log line.
    """
    root = logging.getLogger("hardening_agent")
    root.setLevel(getattr(logging, config.level.upper(), logging.INFO))
    # Never let the agent's logs bubble into a host application's root handlers.
    root.propagate = False
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    formatter: logging.Formatter = JsonFormatter() if config.format == "json" else TextFormatter()

    console = logging.StreamHandler(stream if stream is not None else sys.stderr)
    console.setFormatter(formatter)
    root.addHandler(console)

    if config.file:
        path = Path(config.file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except OSError as exc:
            # A missing log directory must not prevent a security audit from
            # running; warn on the console handler we already installed.
            root.warning(
                "cannot open log file, continuing without it",
                extra={
                    "path": str(path),
                    "error": str(exc),
                },
            )

    return root


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the package namespace."""
    return logging.getLogger(f"hardening_agent.{name}")
