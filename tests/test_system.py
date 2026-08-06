"""The real system interface.

These tests exercise :class:`LocalSystem` against ``tmp_path`` rather than the
live host, so they are safe to run anywhere. The subprocess tests are marked
``integration`` because they execute real binaries.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from hardening_agent.system import LocalSystem, _parse_os_release


class TestOsReleaseParsing:
    def test_strips_quotes(self) -> None:
        values = _parse_os_release('NAME="Ubuntu"\nVERSION_ID="24.04"\n')
        assert values == {"NAME": "Ubuntu", "VERSION_ID": "24.04"}

    def test_ignores_comments_and_blanks(self) -> None:
        values = _parse_os_release("# comment\n\nID=ubuntu\n")
        assert values == {"ID": "ubuntu"}

    def test_handles_values_containing_equals(self) -> None:
        values = _parse_os_release("HOME_URL=https://x/?a=b\n")
        assert values["HOME_URL"] == "https://x/?a=b"

    def test_empty_input(self) -> None:
        assert _parse_os_release(None) == {}
        assert _parse_os_release("") == {}


class TestFileOperations:
    def test_read_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("content", encoding="utf-8")
        assert LocalSystem().read_text(str(target)) == "content"

    def test_missing_file_returns_none_not_an_exception(self, tmp_path: Path) -> None:
        """Checks treat None as 'not applicable'; raising would abort the audit."""
        assert LocalSystem().read_text(str(tmp_path / "absent")) is None

    def test_reading_a_directory_returns_none(self, tmp_path: Path) -> None:
        assert LocalSystem().read_text(str(tmp_path)) is None

    def test_undecodable_bytes_do_not_raise(self, tmp_path: Path) -> None:
        """Binary content in a config path must degrade, not crash the run."""
        target = tmp_path / "binary"
        target.write_bytes(b"\xff\xfe\x00valid")
        assert LocalSystem().read_text(str(target)) is not None

    def test_path_exists(self, tmp_path: Path) -> None:
        system = LocalSystem()
        assert system.path_exists(str(tmp_path))
        assert not system.path_exists(str(tmp_path / "nope"))

    def test_stat_reports_permission_bits_without_type_bits(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("x", encoding="utf-8")
        info = LocalSystem().stat(str(target))
        assert info is not None
        assert info.permission_bits == info.mode & 0o7777
        assert info.is_dir is False

    def test_stat_identifies_directories(self, tmp_path: Path) -> None:
        info = LocalSystem().stat(str(tmp_path))
        assert info is not None
        assert info.is_dir is True

    def test_stat_missing_returns_none(self, tmp_path: Path) -> None:
        assert LocalSystem().stat(str(tmp_path / "absent")) is None


class TestGlob:
    def test_relative_pattern_is_rejected(self) -> None:
        """A relative glob would resolve against the CWD, which is attacker-influenced."""
        with pytest.raises(ValueError, match="must be absolute"):
            LocalSystem().glob("etc/*")

    def test_matches_are_sorted(self, tmp_path: Path) -> None:
        for name in ("c.conf", "a.conf", "b.conf"):
            (tmp_path / name).write_text("x", encoding="utf-8")
        matches = LocalSystem().glob(f"{tmp_path.as_posix()}/*.conf")
        assert [Path(m).name for m in matches] == ["a.conf", "b.conf", "c.conf"]

    def test_no_matches_returns_empty(self, tmp_path: Path) -> None:
        assert LocalSystem().glob(f"{tmp_path.as_posix()}/*.nothing") == ()


class TestAtomicWrite:
    def test_write_then_read(self, tmp_path: Path) -> None:
        target = tmp_path / "out.conf"
        LocalSystem().write_text(str(target), "hello\n")
        assert target.read_text(encoding="utf-8") == "hello\n"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "out.conf"
        LocalSystem().write_text(str(target), "hello\n")
        assert target.exists()

    def test_overwrite_leaves_no_temporary_file(self, tmp_path: Path) -> None:
        """A crash mid-write must never leave a half-written sshd_config."""
        target = tmp_path / "out.conf"
        system = LocalSystem()
        system.write_text(str(target), "first\n")
        system.write_text(str(target), "second\n")
        assert target.read_text(encoding="utf-8") == "second\n"
        assert [p.name for p in tmp_path.iterdir()] == ["out.conf"]

    def test_copy_file_preserves_content(self, tmp_path: Path) -> None:
        source = tmp_path / "src.conf"
        source.write_text("payload", encoding="utf-8")
        destination = tmp_path / "nested" / "dst.conf"
        LocalSystem().copy_file(str(source), str(destination))
        assert destination.read_text(encoding="utf-8") == "payload"


class TestRootDetection:
    def test_is_root_is_false_off_posix(self) -> None:
        """On a dev machine without geteuid we must answer False: the safe
        answer, because it makes remediation refuse to run."""
        if not hasattr(__import__("os"), "geteuid"):
            assert LocalSystem().is_root() is False
        else:
            assert isinstance(LocalSystem().is_root(), bool)


class TestHostInfo:
    def test_populates_every_field(self) -> None:
        info = LocalSystem().host_info()
        for value in (
            info.hostname,
            info.os_name,
            info.os_version,
            info.kernel,
            info.architecture,
            info.virtualization,
        ):
            assert value


@pytest.mark.integration
class TestCommandExecution:
    def test_successful_command(self) -> None:
        result = LocalSystem().run([sys.executable, "-c", "print('hello')"])
        assert result.ok
        assert "hello" in result.stdout

    def test_failing_command_reports_the_code(self) -> None:
        result = LocalSystem().run([sys.executable, "-c", "raise SystemExit(3)"])
        assert not result.ok
        assert result.returncode == 3

    def test_missing_binary_returns_127_not_an_exception(self) -> None:
        result = LocalSystem().run(["definitely-not-a-real-binary-xyz"])
        assert result.returncode == 127
        assert not result.ok

    def test_timeout_is_reported_not_raised(self) -> None:
        """A hung command must not wedge the whole audit."""
        result = LocalSystem().run(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5
        )
        assert result.timed_out
        assert result.returncode == 124

    def test_empty_argv_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            LocalSystem().run([])

    def test_shell_metacharacters_are_not_interpreted(self, tmp_path: Path) -> None:
        """The argv-list contract is what makes command injection impossible."""
        canary = tmp_path / "canary"
        result = LocalSystem().run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", f"; touch {canary}"]
        )
        assert f"; touch {canary}" in result.stdout
        assert not canary.exists()
