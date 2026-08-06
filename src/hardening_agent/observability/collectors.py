"""Host telemetry collectors.

Everything here is derived from ``/proc`` and ``/sys`` through the system
interface, so the collectors are fully unit-testable with a fake filesystem and
have no dependency on ``psutil``.

Scope note: this is deliberately *not* a node_exporter replacement. It collects
the handful of signals that give a hardening report operational context -- is the
box out of disk, is it swapping, how long since boot, is anything logged in. For
full host telemetry, run node_exporter alongside and point it at our textfile
directory.
"""

from __future__ import annotations

from ..logging_setup import get_logger
from ..metrics import NAMESPACE, MetricRegistry
from ..system import SystemInterface

logger = get_logger("collectors")

HOST_NAMESPACE = f"{NAMESPACE}_host"


def collect_host_metrics(
    system: SystemInterface, mounts: tuple[str, ...] = ("/",)
) -> MetricRegistry:
    """Gather host telemetry into a registry.

    Individual collector failures are logged and skipped rather than raised: a
    missing ``/proc/meminfo`` must not prevent disk metrics from being exported.
    """
    registry = MetricRegistry()
    for name, collector in (
        ("uptime", _collect_uptime),
        ("loadavg", _collect_loadavg),
        ("memory", _collect_memory),
        ("cpu", _collect_cpu),
        ("filedescriptors", _collect_file_descriptors),
        ("processes", _collect_processes),
    ):
        try:
            collector(system, registry)
        except Exception as exc:
            logger.warning("collector failed", extra={"collector": name, "error": str(exc)})
    try:
        _collect_filesystems(system, registry, mounts)
    except Exception as exc:
        logger.warning("collector failed", extra={"collector": "filesystem", "error": str(exc)})
    return registry


def _collect_uptime(system: SystemInterface, registry: MetricRegistry) -> None:
    content = system.read_text("/proc/uptime")
    if not content:
        return
    seconds = float(content.split()[0])
    registry.gauge(f"{HOST_NAMESPACE}_uptime_seconds", "Time since the host booted.").add(
        round(seconds, 2)
    )


def _collect_loadavg(system: SystemInterface, registry: MetricRegistry) -> None:
    content = system.read_text("/proc/loadavg")
    if not content:
        return
    fields = content.split()
    if len(fields) < 3:
        return
    metric = registry.gauge(
        f"{HOST_NAMESPACE}_load_average", "Kernel load average over 1, 5 and 15 minutes."
    )
    for window, raw in zip(("1m", "5m", "15m"), fields[:3], strict=True):
        metric.add(float(raw), window=window)


def _collect_memory(system: SystemInterface, registry: MetricRegistry) -> None:
    content = system.read_text("/proc/meminfo")
    if not content:
        return
    values = _parse_meminfo(content)
    metric = registry.gauge(f"{HOST_NAMESPACE}_memory_bytes", "Memory by kind, in bytes.")
    for key, label in (
        ("MemTotal", "total"),
        ("MemFree", "free"),
        ("MemAvailable", "available"),
        ("Buffers", "buffers"),
        ("Cached", "cached"),
        ("SwapTotal", "swap_total"),
        ("SwapFree", "swap_free"),
    ):
        if key in values:
            metric.add(values[key], kind=label)

    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable")
    if total and available is not None:
        used_ratio = (total - available) / total * 100.0
        registry.gauge(
            f"{HOST_NAMESPACE}_memory_used_percent",
            "Percentage of physical memory in use (total minus available).",
        ).add(round(used_ratio, 2))


def _parse_meminfo(content: str) -> dict[str, int]:
    """Parse /proc/meminfo, normalising kB values to bytes."""
    values: dict[str, int] = {}
    for line in content.splitlines():
        key, _, remainder = line.partition(":")
        parts = remainder.split()
        if not parts:
            continue
        try:
            amount = int(parts[0])
        except ValueError:
            continue
        # /proc/meminfo reports in kB unless the unit is absent (e.g. HugePages_*)
        if len(parts) > 1 and parts[1].lower() == "kb":
            amount *= 1024
        values[key.strip()] = amount
    return values


def _collect_cpu(system: SystemInterface, registry: MetricRegistry) -> None:
    """Export cumulative CPU seconds per mode.

    Counters, not a percentage: exporting an instantaneous "CPU %" from a single
    sample would require the agent to sleep and sample twice. Prometheus computes
    utilisation from a counter with rate() far more accurately.
    """
    content = system.read_text("/proc/stat")
    if not content:
        return
    first_line = content.splitlines()[0] if content.splitlines() else ""
    if not first_line.startswith("cpu "):
        return
    fields = first_line.split()[1:]
    modes = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    # USER_HZ is 100 on every mainstream Linux configuration.
    user_hz = 100.0
    metric = registry.counter(
        f"{HOST_NAMESPACE}_cpu_seconds_total", "Cumulative CPU time per mode, in seconds."
    )
    for mode, raw in zip(modes, fields, strict=False):
        try:
            metric.add(round(int(raw) / user_hz, 2), mode=mode)
        except ValueError:
            continue

    cpu_count = sum(
        1 for line in content.splitlines() if line.startswith("cpu") and line[3:4].isdigit()
    )
    if cpu_count:
        registry.gauge(f"{HOST_NAMESPACE}_cpu_count", "Number of logical CPUs.").add(cpu_count)


def _collect_filesystems(
    system: SystemInterface, registry: MetricRegistry, mounts: tuple[str, ...]
) -> None:
    """Report usage for the configured mount points.

    Reads /proc/mounts to determine which of the configured paths are real mount
    points, then queries each one. Configured paths that are not mounted are
    skipped silently -- /home is frequently not a separate filesystem, and
    reporting it as a missing disk would be noise.

    Capacity is fetched through the system interface rather than ``os.statvfs``
    directly, so a container inspecting the host at /host reports the host's
    disks instead of its own overlay filesystem.
    """
    mounts_content = system.read_text("/proc/mounts") or ""
    mounted = {line.split()[1] for line in mounts_content.splitlines() if len(line.split()) >= 2}

    size_metric = registry.gauge(
        f"{HOST_NAMESPACE}_filesystem_size_bytes", "Total size of the filesystem."
    )
    avail_metric = registry.gauge(
        f"{HOST_NAMESPACE}_filesystem_avail_bytes",
        "Space available to unprivileged users.",
    )
    used_pct_metric = registry.gauge(
        f"{HOST_NAMESPACE}_filesystem_used_percent", "Percentage of filesystem capacity used."
    )

    for mount in mounts:
        if mount not in mounted and mount != "/":
            continue
        stats = system.filesystem_stats(mount)
        if stats is None:
            continue
        size_metric.add(stats.total_bytes, mountpoint=mount)
        avail_metric.add(stats.available_bytes, mountpoint=mount)
        used_pct_metric.add(stats.used_percent, mountpoint=mount)


def _collect_file_descriptors(system: SystemInterface, registry: MetricRegistry) -> None:
    content = system.read_text("/proc/sys/fs/file-nr")
    if not content:
        return
    fields = content.split()
    if len(fields) < 3:
        return
    registry.gauge(
        f"{HOST_NAMESPACE}_file_descriptors_allocated", "File descriptors currently allocated."
    ).add(int(fields[0]))
    registry.gauge(
        f"{HOST_NAMESPACE}_file_descriptors_max", "System-wide file descriptor limit."
    ).add(int(fields[2]))


def _collect_processes(system: SystemInterface, registry: MetricRegistry) -> None:
    """Count running processes by enumerating numeric /proc entries."""
    entries = system.glob("/proc/[0-9]*")
    if not entries:
        return
    registry.gauge(f"{HOST_NAMESPACE}_processes", "Number of processes visible in /proc.").add(
        len(entries)
    )
