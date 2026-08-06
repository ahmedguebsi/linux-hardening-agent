"""Configuration loading, validation and precedence."""

from __future__ import annotations

import pytest

from hardening_agent.config import (
    Config,
    ConfigError,
    ExporterConfig,
    RemediationConfig,
    find_config_file,
    load_config,
)
from hardening_agent.models import Severity


def write_config(tmp_path, content: str) -> str:
    path = tmp_path / "agent.toml"
    path.write_text(content, encoding="utf-8")
    return str(path)


class TestDefaults:
    def test_defaults_are_valid(self) -> None:
        Config().validate()

    def test_secure_defaults(self) -> None:
        """The out-of-the-box posture must be safe without any configuration."""
        config = Config()
        assert config.remediation.enabled is False
        assert config.remediation.allow_risky is False
        # Metrics reveal exactly how the host is weak; loopback by default.
        assert config.exporter.host == "127.0.0.1"
        assert config.logging.include_evidence is False

    def test_missing_file_falls_back_to_defaults(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        config = load_config(None, env={})
        assert config.source_path is None
        assert config.audit.profile == "baseline"


class TestFileLoading:
    def test_values_are_read(self, tmp_path) -> None:
        path = write_config(
            tmp_path,
            """
            [audit]
            profile = "pci"
            min_severity = "medium"
            fail_on_severity = "critical"
            exclude = ["kernel_ip_forwarding_disabled"]

            [exporter]
            port = 9999
            """,
        )
        config = load_config(path, env={})
        assert config.audit.profile == "pci"
        assert config.audit.min_severity is Severity.MEDIUM
        assert config.audit.fail_on_severity is Severity.CRITICAL
        assert config.audit.exclude == ("kernel_ip_forwarding_disabled",)
        assert config.exporter.port == 9999
        assert config.source_path == path

    def test_explicit_missing_path_is_fatal(self, tmp_path) -> None:
        """Silently using defaults when a named config is absent is dangerous."""
        with pytest.raises(ConfigError, match="not found"):
            load_config(str(tmp_path / "nope.toml"), env={})

    def test_invalid_toml_names_the_file(self, tmp_path) -> None:
        path = write_config(tmp_path, "[audit\nprofile = ")
        with pytest.raises(ConfigError, match="invalid TOML"):
            load_config(path, env={})


class TestTypoRejection:
    """Unknown keys are fatal: a typo'd control silently doing nothing is a bug."""

    def test_unknown_key_in_section_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, '[audit]\nfail_on_severty = "high"\n')
        with pytest.raises(ConfigError) as exc:
            load_config(path, env={})
        assert "fail_on_severty" in str(exc.value)
        assert "allowed" in str(exc.value)

    def test_unknown_top_level_section_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, '[auditing]\nprofile = "x"\n')
        with pytest.raises(ConfigError, match="auditing"):
            load_config(path, env={})

    def test_wrong_type_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, '[exporter]\nport = "9101"\n')
        with pytest.raises(ConfigError, match="port must be an integer"):
            load_config(path, env={})

    def test_bare_string_where_array_expected_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, '[audit]\ninclude = "ssh_root_login_disabled"\n')
        with pytest.raises(ConfigError, match="array of strings"):
            load_config(path, env={})

    def test_unknown_severity_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, '[audit]\nmin_severity = "extreme"\n')
        with pytest.raises(ConfigError, match="unknown severity"):
            load_config(path, env={})


class TestValidation:
    def test_include_exclude_overlap_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, '[audit]\ninclude = ["a"]\nexclude = ["a"]\n')
        with pytest.raises(ConfigError, match="overlap"):
            load_config(path, env={})

    @pytest.mark.parametrize("port", [0, -1, 70000])
    def test_out_of_range_port_is_rejected(self, port: int) -> None:
        with pytest.raises(ConfigError, match="1-65535"):
            ExporterConfig(port=port).validate()

    def test_too_frequent_refresh_is_rejected(self) -> None:
        """A sub-5s audit loop would peg the CPU of the host it is monitoring."""
        with pytest.raises(ConfigError, match=">= 5 seconds"):
            ExporterConfig(refresh_interval=1.0).validate()

    def test_relative_backup_dir_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="absolute path"):
            RemediationConfig(backup_dir="backups").validate()

    def test_textfile_name_must_end_in_prom(self, tmp_path) -> None:
        path = write_config(tmp_path, '[metrics]\ntextfile_name = "metrics.txt"\n')
        with pytest.raises(ConfigError, match=r"\.prom"):
            load_config(path, env={})


class TestEnvironmentOverrides:
    def test_env_overrides_file(self, tmp_path) -> None:
        path = write_config(tmp_path, '[audit]\nprofile = "from-file"\n')
        config = load_config(path, env={"HARDENING_AGENT_PROFILE": "from-env"})
        assert config.audit.profile == "from-env"

    def test_list_values_split_on_comma(self, tmp_path) -> None:
        path = write_config(tmp_path, "")
        config = load_config(path, env={"HARDENING_AGENT_EXCLUDE": "a, b ,c"})
        assert config.audit.exclude == ("a", "b", "c")

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("true", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("0", False),
            ("no", False),
            ("off", False),
        ],
    )
    def test_boolean_forms(self, tmp_path, value: str, expected: bool) -> None:
        path = write_config(tmp_path, "")
        config = load_config(path, env={"HARDENING_AGENT_EXPORTER_ENABLED": value})
        assert config.exporter.enabled is expected

    def test_invalid_boolean_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, "")
        with pytest.raises(ConfigError, match="boolean-like"):
            load_config(path, env={"HARDENING_AGENT_EXPORTER_ENABLED": "maybe"})

    def test_invalid_int_is_rejected(self, tmp_path) -> None:
        path = write_config(tmp_path, "")
        with pytest.raises(ConfigError, match="must be an integer"):
            load_config(path, env={"HARDENING_AGENT_EXPORTER_PORT": "http"})


class TestDerivedValues:
    def test_textfile_path_joins_correctly(self) -> None:
        config = Config()
        assert config.textfile_path == "/var/lib/hardening-agent/textfile/hardening_agent.prom"

    def test_trailing_slash_does_not_double_up(self, tmp_path) -> None:
        path = write_config(tmp_path, '[metrics]\ntextfile_dir = "/var/lib/x/"\n')
        config = load_config(path, env={})
        assert config.textfile_path == "/var/lib/x/hardening_agent.prom"


class TestFindConfigFile:
    def test_returns_none_when_nothing_exists(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert find_config_file(None) is None

    def test_finds_local_config_directory(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "agent.toml").write_text("", encoding="utf-8")
        assert find_config_file(None) == "./config/agent.toml"
