"""Host telemetry collectors and atomic textfile publication."""

from __future__ import annotations

from pathlib import Path

import pytest

from hardening_agent.observability.collectors import _parse_meminfo, collect_host_metrics
from hardening_agent.observability.textfile import TextfileWriteError, write_textfile
from tests.conftest import FakeSystem


class TestMeminfoParsing:
    def test_kb_values_converted_to_bytes(self) -> None:
        values = _parse_meminfo("MemTotal:       16384 kB\n")
        assert values["MemTotal"] == 16384 * 1024

    def test_unitless_values_left_alone(self) -> None:
        values = _parse_meminfo("HugePages_Total:    0\n")
        assert values["HugePages_Total"] == 0

    def test_malformed_lines_skipped(self) -> None:
        values = _parse_meminfo("garbage\nMemFree:  100 kB\nAnother:\n")
        assert values == {"MemFree": 100 * 1024}


class TestCollectors:
    def test_uptime(self, fake_system: FakeSystem) -> None:
        fake_system.files["/proc/uptime"] = "12345.67 98765.43\n"
        rendered = collect_host_metrics(fake_system).render()
        assert "hardening_agent_host_uptime_seconds 12345.67" in rendered

    def test_load_average_labelled_by_window(self, fake_system: FakeSystem) -> None:
        fake_system.files["/proc/loadavg"] = "0.52 0.58 0.59 1/523 12345\n"
        rendered = collect_host_metrics(fake_system).render()
        assert 'hardening_agent_host_load_average{window="1m"} 0.52' in rendered
        assert 'hardening_agent_host_load_average{window="15m"} 0.59' in rendered

    def test_memory_and_used_percentage(self, fake_system: FakeSystem) -> None:
        fake_system.files["/proc/meminfo"] = (
            "MemTotal:       1000 kB\nMemFree:  200 kB\nMemAvailable:  400 kB\n"
        )
        rendered = collect_host_metrics(fake_system).render()
        assert 'hardening_agent_host_memory_bytes{kind="total"} 1024000' in rendered
        # (1000 - 400) / 1000 = 60%
        assert "hardening_agent_host_memory_used_percent 60.0" in rendered

    def test_cpu_exported_as_counter_in_seconds(self, fake_system: FakeSystem) -> None:
        """Counters let Prometheus compute utilisation with rate()."""
        fake_system.files["/proc/stat"] = (
            "cpu  10000 200 3000 900000 500 0 100 0\ncpu0 1 1 1 1 1 1 1 1\ncpu1 1 1 1 1 1 1 1 1\n"
        )
        rendered = collect_host_metrics(fake_system).render()
        assert "# TYPE hardening_agent_host_cpu_seconds_total counter" in rendered
        assert 'hardening_agent_host_cpu_seconds_total{mode="user"} 100.0' in rendered
        assert "hardening_agent_host_cpu_count 2" in rendered

    def test_file_descriptors(self, fake_system: FakeSystem) -> None:
        fake_system.files["/proc/sys/fs/file-nr"] = "1024\t0\t9223372036854775807\n"
        rendered = collect_host_metrics(fake_system).render()
        assert "hardening_agent_host_file_descriptors_allocated 1024" in rendered

    def test_process_count(self, fake_system: FakeSystem) -> None:
        for pid in ("1", "42", "1337"):
            fake_system.directories.add(f"/proc/{pid}")
        fake_system.directories.add("/proc/self")  # non-numeric, must be excluded
        rendered = collect_host_metrics(fake_system).render()
        assert "hardening_agent_host_processes 3" in rendered

    def test_filesystem_capacity_for_mounted_paths(self, fake_system: FakeSystem) -> None:
        from hardening_agent.system import FilesystemStats

        fake_system.files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /var ext4 rw 0 0\n"
        fake_system.filesystems["/"] = FilesystemStats(
            total_bytes=1000, available_bytes=250, used_bytes=750
        )
        rendered = collect_host_metrics(fake_system, ("/", "/var")).render()
        assert 'hardening_agent_host_filesystem_size_bytes{mountpoint="/"} 1000' in rendered
        assert 'hardening_agent_host_filesystem_used_percent{mountpoint="/"} 75.0' in rendered

    def test_unmounted_configured_path_is_skipped(self, fake_system: FakeSystem) -> None:
        """/home is often not its own filesystem; that is not a missing disk."""
        fake_system.files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\n"
        rendered = collect_host_metrics(fake_system, ("/home",)).render()
        assert "filesystem_size_bytes" not in rendered

    def test_missing_proc_files_produce_no_metrics_not_a_crash(
        self, fake_system: FakeSystem
    ) -> None:
        assert collect_host_metrics(fake_system).render() == "\n"

    def test_one_bad_collector_does_not_break_the_others(self, fake_system: FakeSystem) -> None:
        """A malformed /proc/loadavg must not suppress uptime."""
        fake_system.files["/proc/uptime"] = "100.0 200.0\n"
        fake_system.files["/proc/loadavg"] = "not a number at all\n"
        rendered = collect_host_metrics(fake_system).render()
        assert "hardening_agent_host_uptime_seconds 100.0" in rendered


class TestTextfileWriting:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = tmp_path / "metrics.prom"
        write_textfile(str(target), "metric 1\n")
        assert target.read_text(encoding="utf-8") == "metric 1\n"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "deeper" / "metrics.prom"
        write_textfile(str(target), "metric 1\n")
        assert target.exists()

    def test_trailing_newline_added(self, tmp_path: Path) -> None:
        """A file without a final newline makes node_exporter drop the scrape."""
        target = tmp_path / "metrics.prom"
        write_textfile(str(target), "metric 1")
        assert target.read_text(encoding="utf-8").endswith("\n")

    def test_overwrites_atomically(self, tmp_path: Path) -> None:
        target = tmp_path / "metrics.prom"
        write_textfile(str(target), "old 1\n")
        write_textfile(str(target), "new 2\n")
        assert target.read_text(encoding="utf-8") == "new 2\n"

    def test_no_temporary_files_left_behind(self, tmp_path: Path) -> None:
        """A stale .tmp in the textfile dir would be scraped as garbage."""
        target = tmp_path / "metrics.prom"
        write_textfile(str(target), "metric 1\n")
        assert [p.name for p in tmp_path.iterdir()] == ["metrics.prom"]

    def test_unwritable_directory_raises_a_typed_error(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file, not a directory", encoding="utf-8")
        with pytest.raises(TextfileWriteError):
            write_textfile(str(blocker / "metrics.prom"), "metric 1\n")

    def test_reader_never_sees_partial_content(self, tmp_path: Path) -> None:
        """The rename is what guarantees this; assert the file is never empty."""
        target = tmp_path / "metrics.prom"
        payload = "x" * 100_000 + "\n"
        write_textfile(str(target), payload)
        assert target.read_text(encoding="utf-8") == payload
