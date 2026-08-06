"""Prometheus HTTP exporter.

Built on :mod:`http.server` to preserve the zero-runtime-dependency property.
That is an acceptable trade here because the exposed surface is three read-only
GET endpoints bound to loopback by default, serving a handful of clients -- not a
public web application.

Endpoints
---------
``GET /metrics``
    Prometheus exposition of the cached audit plus live host telemetry.
``GET /healthz``
    Liveness. Returns 200 whenever the process is running.
``GET /readyz``
    Readiness. Returns 503 until the first audit has completed, so an
    orchestrator does not route scrapes at a process with no data yet.

Concurrency model: audits run on a background thread on a fixed interval, and the
result is published to a lock-protected cache. HTTP handlers only ever read the
cache. A scrape therefore never blocks on a multi-second audit, and a slow
scraper cannot stack up concurrent audits.
"""

from __future__ import annotations

import json
import signal
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .config import Config
from .logging_setup import get_logger
from .metrics import NAMESPACE, MetricRegistry, build_report_metrics
from .models import Report
from .observability import collect_host_metrics, write_textfile
from .runner import AuditRunner

logger = get_logger("exporter")

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class MetricsCache:
    """Thread-safe holder for the most recent audit result."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._report: Report | None = None
        self._rendered: str = ""
        self._updated_at: float = 0.0
        self._run_count: int = 0
        self._error_count: int = 0
        self._last_error: str | None = None

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._report is not None

    def publish(self, report: Report, rendered: str) -> None:
        with self._lock:
            self._report = report
            self._rendered = rendered
            self._updated_at = time.time()
            self._run_count += 1

    def record_error(self, message: str) -> None:
        with self._lock:
            self._error_count += 1
            self._last_error = message

    def snapshot(self) -> tuple[str, float, int, int, str | None]:
        with self._lock:
            return (
                self._rendered,
                self._updated_at,
                self._run_count,
                self._error_count,
                self._last_error,
            )


class AuditScheduler:
    """Runs audits on an interval in a daemon thread."""

    def __init__(
        self,
        runner: AuditRunner,
        config: Config,
        cache: MetricsCache,
    ) -> None:
        self._runner = runner
        self._config = config
        self._cache = cache
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("scheduler already started")
        self._thread = threading.Thread(
            target=self._loop, name="hardening-agent-audit", daemon=True
        )
        self._thread.start()
        logger.info(
            "audit scheduler started",
            extra={"interval_seconds": self._config.exporter.refresh_interval},
        )

    def stop(self, timeout: float = 30.0) -> None:
        """Signal the loop to stop and wait for the in-flight audit to finish.

        Waiting matters: killing the thread mid-audit could leave a partially
        applied remediation. The exporter never remediates, but the scheduler is
        shared machinery, so it shuts down cleanly by contract.
        """
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(
                    "audit thread did not stop within timeout", extra={"timeout": timeout}
                )
        logger.info("audit scheduler stopped")

    def run_once(self) -> None:
        """Execute one audit and publish the result. Exceptions are contained."""
        try:
            report = self._runner.run(remediate=False, dry_run=False)
            registry = build_report_metrics(report)
            if self._config.metrics.host_metrics:
                registry.merge(
                    collect_host_metrics(self._runner.system, self._config.metrics.monitored_mounts)
                )
            rendered = registry.render()
            self._cache.publish(report, rendered)

            if self._config.metrics.enabled:
                try:
                    write_textfile(self._config.textfile_path, rendered)
                except OSError as exc:
                    # A failed textfile write must not stop the HTTP exporter
                    # from serving; they are independent publication paths.
                    logger.warning("textfile write failed", extra={"error": str(exc)})
        except Exception as exc:
            logger.exception("audit run failed", extra={"error": str(exc)})
            self._cache.record_error(str(exc))

    def _loop(self) -> None:
        # Run immediately on start so /readyz turns green without waiting a
        # full interval.
        self.run_once()
        interval = self._config.exporter.refresh_interval
        while not self._stop.wait(interval):
            self.run_once()


class MetricsHandler(BaseHTTPRequestHandler):
    """Read-only HTTP handler. Injected dependencies live on the server."""

    server_version = "hardening-agent"
    sys_version = ""  # do not advertise the Python version
    protocol_version = "HTTP/1.1"  # required for keep-alive and Content-Length

    # Injected by ExporterServer
    cache: MetricsCache
    config: Config

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        match path:
            case "/metrics":
                self._serve_metrics()
            case "/healthz":
                self._serve_json(HTTPStatus.OK, {"status": "ok"})
            case "/readyz":
                self._serve_readiness()
            case "/":
                self._serve_index()
            case _:
                self._serve_json(HTTPStatus.NOT_FOUND, {"error": "not found", "path": path})

    def do_POST(self) -> None:
        """Reject writes explicitly: this exporter has no mutating endpoints."""
        self._serve_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})

    # Names are dictated by BaseHTTPRequestHandler's dispatch (`do_<METHOD>`),
    # so the mixedCase naming rule does not apply here.
    do_PUT = do_POST  # noqa: N815
    do_DELETE = do_POST  # noqa: N815
    do_PATCH = do_POST  # noqa: N815

    def _serve_metrics(self) -> None:
        rendered, updated_at, run_count, error_count, _ = self.cache.snapshot()
        if not rendered:
            self._serve_json(
                HTTPStatus.SERVICE_UNAVAILABLE, {"error": "no audit has completed yet"}
            )
            return
        # Self-observability: the exporter reports on its own health alongside
        # the host's. If scrape_staleness climbs, the audit thread has wedged.
        meta = MetricRegistry()
        meta.counter(f"{NAMESPACE}_exporter_runs_total", "Total audits completed since start.").add(
            run_count
        )
        meta.counter(f"{NAMESPACE}_exporter_errors_total", "Total audit runs that raised.").add(
            error_count
        )
        meta.gauge(
            f"{NAMESPACE}_exporter_metrics_age_seconds",
            "Seconds since the cached audit was published.",
        ).add(round(time.time() - updated_at, 3))
        body = (rendered + meta.render()).encode("utf-8")
        self._send(HTTPStatus.OK, body, CONTENT_TYPE)

    def _serve_readiness(self) -> None:
        _, updated_at, run_count, error_count, last_error = self.cache.snapshot()
        if not self.cache.ready:
            self._serve_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"status": "starting", "detail": "first audit has not completed"},
            )
            return
        age = time.time() - updated_at
        # Stale beyond three intervals means the audit thread is not making
        # progress; report not-ready so an orchestrator can restart us.
        stale_after = self.config.exporter.refresh_interval * 3
        if age > stale_after:
            self._serve_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "status": "stale",
                    "age_seconds": round(age, 1),
                    "stale_after_seconds": round(stale_after, 1),
                    "last_error": last_error,
                },
            )
            return
        self._serve_json(
            HTTPStatus.OK,
            {
                "status": "ready",
                "age_seconds": round(age, 1),
                "runs": run_count,
                "errors": error_count,
            },
        )

    def _serve_index(self) -> None:
        body = (
            b"hardening-agent metrics exporter\n\n"
            b"  GET /metrics   Prometheus exposition\n"
            b"  GET /healthz   liveness probe\n"
            b"  GET /readyz    readiness probe\n"
        )
        self._send(HTTPStatus.OK, body, "text/plain; charset=utf-8")

    def _serve_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload) + "\n").encode("utf-8")
        self._send(status, body, "application/json")

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Defence-in-depth headers; cheap and silence scanner findings.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Route access logs through structured logging instead of stderr."""
        logger.debug(
            "http request",
            extra={
                "client": self.client_address[0] if self.client_address else "unknown",
                "message": format % args,
            },
        )

    def log_error(self, format: str, *args: Any) -> None:  # noqa: A002
        logger.warning(
            "http error",
            extra={
                "client": self.client_address[0] if self.client_address else "unknown",
                "message": format % args,
            },
        )


class ExporterServer(ThreadingHTTPServer):
    """HTTP server carrying the injected cache and config."""

    daemon_threads = True
    # Allow immediate rebinding after restart instead of waiting out TIME_WAIT.
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], cache: MetricsCache, config: Config) -> None:
        handler = type(
            "BoundMetricsHandler",
            (MetricsHandler,),
            {"cache": cache, "config": config, "timeout": config.exporter.request_timeout},
        )
        super().__init__(address, handler)
        self.cache = cache
        self.config = config


def serve(
    runner: AuditRunner,
    config: Config,
    *,
    install_signal_handlers: bool = True,
    ready_event: threading.Event | None = None,
) -> int:
    """Run the exporter until terminated. Returns a process exit code.

    Graceful shutdown sequence on SIGTERM/SIGINT:

    1. Stop accepting new connections (``server.shutdown()``).
    2. Stop the audit scheduler and wait for any in-flight audit.
    3. Close the listening socket.

    systemd sends SIGTERM on ``systemctl stop`` and on deploys; handling it means
    the unit stops in milliseconds instead of waiting out ``TimeoutStopSec``.
    """
    cache = MetricsCache()
    scheduler = AuditScheduler(runner, config, cache)
    server = ExporterServer((config.exporter.host, config.exporter.port), cache, config)

    shutdown_complete = threading.Event()

    def handle_signal(signum: int, _frame: Any) -> None:
        name = signal.Signals(signum).name
        logger.info("shutdown signal received", extra={"signal": name})
        # shutdown() blocks until the serve_forever loop exits, so it must not
        # be called from inside the signal handler's thread context.
        threading.Thread(target=_shutdown, name="hardening-agent-shutdown").start()

    def _shutdown() -> None:
        server.shutdown()
        shutdown_complete.set()

    if install_signal_handlers:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, handle_signal)

    scheduler.start()
    logger.info(
        "exporter listening",
        extra={
            "host": config.exporter.host,
            "port": config.exporter.port,
            "endpoints": ["/metrics", "/healthz", "/readyz"],
        },
    )
    if ready_event is not None:
        ready_event.set()

    exit_code = 0
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        logger.info("interrupted")
    except OSError as exc:
        logger.error("server failed", extra={"error": str(exc)})
        exit_code = 1
    finally:
        scheduler.stop()
        server.server_close()
        shutdown_complete.set()
        logger.info("exporter stopped")
    return exit_code
