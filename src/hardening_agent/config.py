"""Configuration loading and validation.

Config is TOML parsed with the standard library's :mod:`tomllib`. That is a
deliberate choice: this agent runs as root on production hosts, so it ships with
**zero runtime third-party dependencies**. No YAML parser, no settings library,
nothing to CVE-patch on a fleet of machines.

Precedence, lowest to highest:

1. Built-in defaults (this module)
2. The config file
3. ``HARDENING_AGENT_*`` environment variables
4. CLI flags (applied by :mod:`hardening_agent.cli`)
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .models import Severity

DEFAULT_CONFIG_PATHS: tuple[str, ...] = (
    "/etc/hardening-agent/agent.toml",
    "./config/agent.toml",
)

ENV_PREFIX = "HARDENING_AGENT_"


class ConfigError(ValueError):
    """Raised when configuration is malformed or internally inconsistent.

    Always carries a message naming the offending key so an operator can fix it
    without reading the source.
    """


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"  # "json" | "text"
    file: str | None = None
    include_evidence: bool = False

    def validate(self) -> None:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.level.upper() not in valid_levels:
            raise ConfigError(
                f"logging.level must be one of {sorted(valid_levels)}, got {self.level!r}"
            )
        if self.format not in ("json", "text"):
            raise ConfigError(f"logging.format must be 'json' or 'text', got {self.format!r}")


@dataclass(frozen=True, slots=True)
class ExporterConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 9101
    # Refuse requests that take longer than this to read; protects the exporter
    # from slowloris-style connection exhaustion.
    request_timeout: float = 10.0
    max_request_bytes: int = 8192
    refresh_interval: float = 60.0

    def validate(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"exporter.port must be 1-65535, got {self.port}")
        if self.refresh_interval < 5:
            raise ConfigError(
                f"exporter.refresh_interval must be >= 5 seconds, got {self.refresh_interval}"
            )
        if self.request_timeout <= 0:
            raise ConfigError("exporter.request_timeout must be positive")


@dataclass(frozen=True, slots=True)
class MetricsConfig:
    enabled: bool = True
    textfile_dir: str = "/var/lib/hardening-agent/textfile"
    textfile_name: str = "hardening_agent.prom"
    host_metrics: bool = True
    monitored_mounts: tuple[str, ...] = ("/", "/var", "/tmp", "/home")

    def validate(self) -> None:
        if not self.textfile_name.endswith(".prom"):
            raise ConfigError(
                f"metrics.textfile_name must end with '.prom', got {self.textfile_name!r}"
            )
        if not self.textfile_dir.startswith("/"):
            raise ConfigError("metrics.textfile_dir must be an absolute path")


@dataclass(frozen=True, slots=True)
class RemediationConfig:
    enabled: bool = False
    allow_risky: bool = False
    backup_dir: str = "/var/backups/hardening-agent"
    keep_backups: int = 20

    def validate(self) -> None:
        if self.keep_backups < 1:
            raise ConfigError("remediation.keep_backups must be >= 1")
        if not self.backup_dir.startswith("/"):
            raise ConfigError("remediation.backup_dir must be an absolute path")


@dataclass(frozen=True, slots=True)
class AuditConfig:
    profile: str = "baseline"
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    min_severity: Severity = Severity.LOW
    # Exit non-zero when a failing check is at least this severe. Lets CI gate on
    # HIGH while still reporting LOW findings.
    fail_on_severity: Severity = Severity.HIGH
    check_timeout: float = 20.0

    def validate(self) -> None:
        overlap = set(self.include) & set(self.exclude)
        if overlap:
            raise ConfigError(f"audit.include and audit.exclude overlap on: {sorted(overlap)}")
        if self.check_timeout <= 0:
            raise ConfigError("audit.check_timeout must be positive")


@dataclass(frozen=True, slots=True)
class Config:
    audit: AuditConfig = field(default_factory=AuditConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    exporter: ExporterConfig = field(default_factory=ExporterConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    source_path: str | None = None

    def validate(self) -> Config:
        self.audit.validate()
        self.logging.validate()
        self.exporter.validate()
        self.metrics.validate()
        self.remediation.validate()
        return self

    @property
    def textfile_path(self) -> str:
        return f"{self.metrics.textfile_dir.rstrip('/')}/{self.metrics.textfile_name}"


def find_config_file(explicit: str | None = None) -> str | None:
    """Return the first config file that exists, or ``None``.

    An explicit path that does not exist is an error, not a silent fallback --
    running with unexpected defaults on a production host is worse than failing.
    """
    if explicit:
        if not Path(explicit).is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return explicit
    for candidate in DEFAULT_CONFIG_PATHS:
        if Path(candidate).is_file():
            return candidate
    return None


def load_config(path: str | None = None, *, env: Mapping[str, str] | None = None) -> Config:
    """Build a validated :class:`Config` from file plus environment overrides."""
    env = os.environ if env is None else env
    resolved = find_config_file(path)
    raw: dict[str, Any] = {}
    if resolved:
        try:
            with open(resolved, "rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {resolved}: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"cannot read config {resolved}: {exc}") from exc

    config = _from_mapping(raw, source_path=resolved)
    config = _apply_env_overrides(config, env)
    return config.validate()


def _from_mapping(raw: Mapping[str, Any], *, source_path: str | None) -> Config:
    _reject_unknown(raw, {"audit", "logging", "exporter", "metrics", "remediation"}, "")

    audit_raw = _section(raw, "audit")
    _reject_unknown(
        audit_raw,
        {
            "profile",
            "include",
            "exclude",
            "tags",
            "min_severity",
            "fail_on_severity",
            "check_timeout",
        },
        "audit",
    )
    audit = AuditConfig(
        profile=_str(audit_raw, "profile", "baseline"),
        include=_str_tuple(audit_raw, "include"),
        exclude=_str_tuple(audit_raw, "exclude"),
        tags=_str_tuple(audit_raw, "tags"),
        min_severity=_severity(audit_raw, "min_severity", Severity.LOW),
        fail_on_severity=_severity(audit_raw, "fail_on_severity", Severity.HIGH),
        check_timeout=_float(audit_raw, "check_timeout", 20.0),
    )

    logging_raw = _section(raw, "logging")
    _reject_unknown(logging_raw, {"level", "format", "file", "include_evidence"}, "logging")
    logging_cfg = LoggingConfig(
        level=_str(logging_raw, "level", "INFO").upper(),
        format=_str(logging_raw, "format", "json"),
        file=_optional_str(logging_raw, "file"),
        include_evidence=_bool(logging_raw, "include_evidence", False),
    )

    exporter_raw = _section(raw, "exporter")
    _reject_unknown(
        exporter_raw,
        {"enabled", "host", "port", "request_timeout", "max_request_bytes", "refresh_interval"},
        "exporter",
    )
    exporter = ExporterConfig(
        enabled=_bool(exporter_raw, "enabled", True),
        host=_str(exporter_raw, "host", "127.0.0.1"),
        port=_int(exporter_raw, "port", 9101),
        request_timeout=_float(exporter_raw, "request_timeout", 10.0),
        max_request_bytes=_int(exporter_raw, "max_request_bytes", 8192),
        refresh_interval=_float(exporter_raw, "refresh_interval", 60.0),
    )

    metrics_raw = _section(raw, "metrics")
    _reject_unknown(
        metrics_raw,
        {"enabled", "textfile_dir", "textfile_name", "host_metrics", "monitored_mounts"},
        "metrics",
    )
    metrics = MetricsConfig(
        enabled=_bool(metrics_raw, "enabled", True),
        textfile_dir=_str(metrics_raw, "textfile_dir", "/var/lib/hardening-agent/textfile"),
        textfile_name=_str(metrics_raw, "textfile_name", "hardening_agent.prom"),
        host_metrics=_bool(metrics_raw, "host_metrics", True),
        monitored_mounts=_str_tuple(metrics_raw, "monitored_mounts")
        or ("/", "/var", "/tmp", "/home"),
    )

    remediation_raw = _section(raw, "remediation")
    _reject_unknown(
        remediation_raw, {"enabled", "allow_risky", "backup_dir", "keep_backups"}, "remediation"
    )
    remediation = RemediationConfig(
        enabled=_bool(remediation_raw, "enabled", False),
        allow_risky=_bool(remediation_raw, "allow_risky", False),
        backup_dir=_str(remediation_raw, "backup_dir", "/var/backups/hardening-agent"),
        keep_backups=_int(remediation_raw, "keep_backups", 20),
    )

    return Config(
        audit=audit,
        logging=logging_cfg,
        exporter=exporter,
        metrics=metrics,
        remediation=remediation,
        source_path=source_path,
    )


def _apply_env_overrides(config: Config, env: Mapping[str, str]) -> Config:
    """Apply ``HARDENING_AGENT_<SECTION>_<KEY>`` overrides.

    Environment overrides exist so a container can be reconfigured without
    baking a new image, which is how this agent is deployed in the compose demo.
    """
    audit = config.audit
    logging_cfg = config.logging
    exporter = config.exporter
    metrics = config.metrics
    remediation = config.remediation

    def get(name: str) -> str | None:
        return env.get(f"{ENV_PREFIX}{name}")

    if (value := get("PROFILE")) is not None:
        audit = replace(audit, profile=value)
    if (value := get("INCLUDE")) is not None:
        audit = replace(audit, include=_split_list(value))
    if (value := get("EXCLUDE")) is not None:
        audit = replace(audit, exclude=_split_list(value))
    if (value := get("TAGS")) is not None:
        audit = replace(audit, tags=_split_list(value))
    if (value := get("MIN_SEVERITY")) is not None:
        audit = replace(audit, min_severity=_parse_severity_value(value, "MIN_SEVERITY"))
    if (value := get("FAIL_ON_SEVERITY")) is not None:
        audit = replace(audit, fail_on_severity=_parse_severity_value(value, "FAIL_ON_SEVERITY"))

    if (value := get("LOG_LEVEL")) is not None:
        logging_cfg = replace(logging_cfg, level=value.upper())
    if (value := get("LOG_FORMAT")) is not None:
        logging_cfg = replace(logging_cfg, format=value.lower())
    if (value := get("LOG_FILE")) is not None:
        logging_cfg = replace(logging_cfg, file=value or None)

    if (value := get("EXPORTER_ENABLED")) is not None:
        exporter = replace(exporter, enabled=_parse_bool(value, "EXPORTER_ENABLED"))
    if (value := get("EXPORTER_HOST")) is not None:
        exporter = replace(exporter, host=value)
    if (value := get("EXPORTER_PORT")) is not None:
        exporter = replace(exporter, port=_parse_int(value, "EXPORTER_PORT"))
    if (value := get("EXPORTER_REFRESH_INTERVAL")) is not None:
        exporter = replace(
            exporter, refresh_interval=_parse_float(value, "EXPORTER_REFRESH_INTERVAL")
        )

    if (value := get("TEXTFILE_DIR")) is not None:
        metrics = replace(metrics, textfile_dir=value)
    if (value := get("METRICS_ENABLED")) is not None:
        metrics = replace(metrics, enabled=_parse_bool(value, "METRICS_ENABLED"))

    if (value := get("REMEDIATION_ENABLED")) is not None:
        remediation = replace(remediation, enabled=_parse_bool(value, "REMEDIATION_ENABLED"))
    if (value := get("REMEDIATION_ALLOW_RISKY")) is not None:
        remediation = replace(
            remediation, allow_risky=_parse_bool(value, "REMEDIATION_ALLOW_RISKY")
        )
    if (value := get("BACKUP_DIR")) is not None:
        remediation = replace(remediation, backup_dir=value)

    return replace(
        config,
        audit=audit,
        logging=logging_cfg,
        exporter=exporter,
        metrics=metrics,
        remediation=remediation,
    )


# -- typed accessors -------------------------------------------------------
def _section(raw: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, Mapping):
        raise ConfigError(f"[{name}] must be a table, got {type(value).__name__}")
    return value


def _reject_unknown(raw: Mapping[str, Any], allowed: set[str], section: str) -> None:
    """Fail loudly on typos rather than silently ignoring them.

    A silently-ignored ``fail_on_severty`` typo means an operator believes a gate
    is active when it is not. That is a security bug, so unknown keys are fatal.
    """
    unknown = set(raw) - allowed
    if unknown:
        where = f"[{section}]" if section else "top level"
        raise ConfigError(
            f"unknown configuration key(s) at {where}: {sorted(unknown)}; "
            f"allowed: {sorted(allowed)}"
        )


def _str(raw: Mapping[str, Any], key: str, default: str) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string, got {type(value).__name__}")
    return value


def _optional_str(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string, got {type(value).__name__}")
    return value or None


def _bool(raw: Mapping[str, Any], key: str, default: bool) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be a boolean, got {type(value).__name__}")
    return value


def _int(raw: Mapping[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer, got {type(value).__name__}")
    return value


def _float(raw: Mapping[str, Any], key: str, default: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{key} must be a number, got {type(value).__name__}")
    return float(value)


def _str_tuple(raw: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = raw.get(key, ())
    if isinstance(value, str):
        raise ConfigError(f"{key} must be an array of strings, not a bare string")
    if not isinstance(value, Sequence):
        raise ConfigError(f"{key} must be an array of strings, got {type(value).__name__}")
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{key} entries must be strings, got {type(item).__name__}")
    return tuple(value)


def _severity(raw: Mapping[str, Any], key: str, default: Severity) -> Severity:
    value = raw.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string, got {type(value).__name__}")
    return _parse_severity_value(value, key)


def _parse_severity_value(value: str, key: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{key}: {exc}") from exc


def _parse_bool(value: str, key: str) -> bool:
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{ENV_PREFIX}{key} must be a boolean-like value, got {value!r}")


def _parse_int(value: str, key: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{ENV_PREFIX}{key} must be an integer, got {value!r}") from exc


def _parse_float(value: str, key: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"{ENV_PREFIX}{key} must be a number, got {value!r}") from exc


def _split_list(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())
