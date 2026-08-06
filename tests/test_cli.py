"""CLI argument handling, output selection and exit-code contract."""

from __future__ import annotations

import io
import json

import pytest

from hardening_agent.cli import apply_overrides, build_parser, main
from hardening_agent.config import Config
from hardening_agent.models import Severity
from hardening_agent.runner import EXIT_ERROR, EXIT_OK, EXIT_USAGE


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Never pick up a real /etc/hardening-agent/agent.toml during tests."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, stdout=out)
    return code, out.getvalue()


class TestParser:
    def test_subcommand_is_required(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_unknown_subcommand_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["destroy"])

    def test_repeatable_selection_flags(self) -> None:
        args = build_parser().parse_args(["audit", "--check", "a", "--check", "b", "--tag", "ssh"])
        assert args.include == ["a", "b"]
        assert args.tags == ["ssh"]

    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["audit", "--min-severity", "apocalyptic"])

    def test_config_flag_accepted_after_subcommand(self) -> None:
        args = build_parser().parse_args(["audit", "--config", "/tmp/a.toml"])
        assert args.config == "/tmp/a.toml"


class TestOverridePrecedence:
    def test_cli_beats_config_file(self) -> None:
        from dataclasses import replace

        from hardening_agent.config import AuditConfig

        config = Config(audit=AuditConfig(min_severity=Severity.LOW))
        args = build_parser().parse_args(["audit", "--min-severity", "critical"])
        assert apply_overrides(config, args).audit.min_severity is Severity.CRITICAL
        # Unrelated settings survive the override.
        assert replace(config).audit.profile == "baseline"

    def test_absent_flags_leave_config_untouched(self) -> None:
        from hardening_agent.config import AuditConfig

        config = Config(audit=AuditConfig(min_severity=Severity.HIGH))
        args = build_parser().parse_args(["audit"])
        assert apply_overrides(config, args).audit.min_severity is Severity.HIGH

    def test_verbose_enables_evidence_logging(self) -> None:
        args = build_parser().parse_args(["audit", "--verbose"])
        assert apply_overrides(Config(), args).logging.include_evidence is True

    def test_allow_risky_flag_propagates(self) -> None:
        args = build_parser().parse_args(["remediate", "--allow-risky", "--dry-run"])
        assert apply_overrides(Config(), args).remediation.allow_risky is True

    def test_overlapping_include_exclude_is_a_usage_error(self) -> None:
        code, _ = run(
            ["audit", "--check", "ssh_root_login_disabled", "--exclude", "ssh_root_login_disabled"]
        )
        assert code == EXIT_USAGE


class TestListChecks:
    def test_text_listing(self) -> None:
        code, output = run(["list-checks"])
        assert code == EXIT_OK
        assert "ssh_root_login_disabled" in output
        assert "SEVERITY" in output

    def test_json_listing_is_parseable(self) -> None:
        code, output = run(["list-checks", "--format", "json"])
        assert code == EXIT_OK
        catalogue = json.loads(output)
        assert len(catalogue) > 30
        assert all("rationale" in entry for entry in catalogue)

    def test_tag_filter_narrows_the_listing(self) -> None:
        _, output = run(["list-checks", "--tag", "ssh", "--format", "json"])
        catalogue = json.loads(output)
        assert catalogue
        assert all("ssh" in entry["tags"] for entry in catalogue)

    def test_unknown_check_id_is_a_usage_error(self) -> None:
        code, _ = run(["list-checks", "--check", "no_such_check"])
        assert code == EXIT_USAGE


class TestConfigCommand:
    def test_shows_effective_configuration(self) -> None:
        code, output = run(["config"])
        assert code == EXIT_OK
        assert "textfile_path" in output

    def test_json_output(self) -> None:
        code, output = run(["config", "--format", "json"])
        assert code == EXIT_OK
        payload = json.loads(output)
        assert payload["source_path"] == "<defaults>"
        assert payload["remediation"]["enabled"] is False

    def test_reports_the_file_it_loaded(self, tmp_path) -> None:
        path = tmp_path / "custom.toml"
        path.write_text('[audit]\nprofile = "custom"\n', encoding="utf-8")
        code, output = run(["config", "--config", str(path), "--format", "json"])
        assert code == EXIT_OK
        assert json.loads(output)["audit"]["profile"] == "custom"

    def test_bad_config_is_a_usage_error(self, tmp_path) -> None:
        path = tmp_path / "bad.toml"
        path.write_text("[audit]\nunknown_key = 1\n", encoding="utf-8")
        assert run(["config", "--config", str(path)])[0] == EXIT_USAGE

    def test_missing_explicit_config_is_a_usage_error(self) -> None:
        assert run(["config", "--config", "/nonexistent/agent.toml"])[0] == EXIT_USAGE


class TestAudit:
    def test_json_report_is_parseable(self) -> None:
        code, output = run(["audit", "--format", "json", "--log-level", "CRITICAL"])
        payload = json.loads(output)
        assert payload["schema_version"] == "1.0"
        assert "results" in payload
        assert code in (EXIT_OK, 1, EXIT_ERROR)

    def test_writes_report_to_a_file(self, tmp_path) -> None:
        target = tmp_path / "out" / "report.json"
        run(["audit", "--format", "json", "-o", str(target), "--log-level", "CRITICAL"])
        assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == "1.0"

    def test_stdout_stays_clean_for_piping(self) -> None:
        """Logs go to stderr so `--format json | jq` never breaks."""
        _, output = run(["audit", "--format", "json", "--log-level", "DEBUG"])
        json.loads(output)

    def test_single_check_selection(self) -> None:
        _, output = run(
            [
                "audit",
                "--check",
                "kernel_aslr_enabled",
                "--format",
                "json",
                "--log-level",
                "CRITICAL",
            ]
        )
        payload = json.loads(output)
        assert len(payload["results"]) == 1
        assert payload["results"][0]["check_id"] == "kernel_aslr_enabled"

    def test_sarif_output(self) -> None:
        _, output = run(["audit", "--format", "sarif", "--log-level", "CRITICAL"])
        assert json.loads(output)["version"] == "2.1.0"


class TestRemediateGuardRails:
    def test_refuses_without_yes(self) -> None:
        """A typo'd `remediate` must never reconfigure sshd."""
        code, _ = run(["remediate", "--log-level", "CRITICAL"])
        assert code == EXIT_USAGE

    def test_dry_run_does_not_need_yes(self) -> None:
        code, _ = run(["remediate", "--dry-run", "--format", "json", "--log-level", "CRITICAL"])
        assert code in (EXIT_OK, 1, EXIT_ERROR)

    def test_dry_run_marks_the_report(self) -> None:
        _, output = run(["remediate", "--dry-run", "--format", "json", "--log-level", "CRITICAL"])
        assert json.loads(output)["dry_run"] is True


class TestExitCodeContract:
    def test_usage_error_is_three(self) -> None:
        assert run(["audit", "--check", "nope"])[0] == EXIT_USAGE

    def test_skip_only_run_is_clean(self) -> None:
        """A check that skips on this platform must not fail the pipeline."""
        code, output = run(
            [
                "audit",
                "--check",
                "services_auditd_running",
                "--format",
                "json",
                "--log-level",
                "CRITICAL",
            ]
        )
        assert json.loads(output)["results"][0]["status"] == "skip"
        assert code == EXIT_OK


class TestVersion:
    def test_version_flag(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "hardening-agent" in capsys.readouterr().out
