"""HTTP exporter: endpoints, readiness semantics, and graceful shutdown.

Marked ``integration`` because these bind a real socket on loopback. They use
port 0 so the OS assigns a free port and parallel runs cannot collide.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from hardening_agent.checks.base import Check, CheckContext
from hardening_agent.config import Config, ExporterConfig, MetricsConfig
from hardening_agent.exporter import AuditScheduler, ExporterServer, MetricsCache
from hardening_agent.models import CheckMetadata, Finding, Severity
from hardening_agent.registry import CheckRegistry
from hardening_agent.runner import AuditRunner
from tests.conftest import FakeSystem

pytestmark = pytest.mark.integration


class AlwaysPasses(Check):
    metadata = CheckMetadata(
        check_id="always_passes",
        title="Always passes",
        description="d",
        severity=Severity.LOW,
        rationale="r",
        tags=frozenset({"test"}),
    )

    def audit(self, ctx: CheckContext) -> Finding:
        return Finding.passed("fine")


@pytest.fixture
def config() -> Config:
    # The configured port is never used for binding here -- the fixture below
    # binds port 0 explicitly so the OS assigns a free one. Config keeps a valid
    # port because port 0 in a real config file is an operator mistake and the
    # validator is right to reject it.
    return Config(
        exporter=ExporterConfig(host="127.0.0.1", port=9101, refresh_interval=5.0),
        # Never touch the real /var during tests.
        metrics=MetricsConfig(enabled=False),
    ).validate()


@pytest.fixture
def runner(config: Config) -> AuditRunner:
    return AuditRunner(CheckRegistry([AlwaysPasses()]), FakeSystem(), config, agent_version="test")


ServerFixture = tuple[str, MetricsCache, AuditScheduler]


@pytest.fixture
def server(config: Config, runner: AuditRunner) -> Iterator[ServerFixture]:
    cache = MetricsCache()
    scheduler = AuditScheduler(runner, config, cache)
    httpd = ExporterServer(("127.0.0.1", 0), cache, config)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base, cache, scheduler
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _request(url: str, *, method: str = "GET", data: bytes | None = None):
    """Build a request that closes its connection.

    The exporter speaks HTTP/1.1, so without an explicit ``Connection: close``
    the client keeps the socket alive and it is still open when the test ends,
    producing a ResourceWarning that `filterwarnings = ["error"]` turns fatal.
    """
    # S310: every URL here is a fixed http:// loopback address built from the
    # fixture's own port, never attacker-influenced input.
    return urllib.request.Request(  # noqa: S310
        url, data=data, method=method, headers={"Connection": "close"}
    )


def get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(_request(url), timeout=5) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read().decode("utf-8")
        finally:
            exc.close()


def get_headers(url: str) -> dict[str, str]:
    with urllib.request.urlopen(_request(url), timeout=5) as response:  # noqa: S310
        return dict(response.headers)


class TestHealthAndReadiness:
    def test_healthz_is_up_before_any_audit(self, server) -> None:
        """Liveness must not depend on the audit; otherwise a slow first audit
        gets the process killed by an orchestrator."""
        base, _, _ = server
        status, body = get(f"{base}/healthz")
        assert status == 200
        assert json.loads(body)["status"] == "ok"

    def test_readyz_is_503_until_the_first_audit(self, server) -> None:
        base, _, _ = server
        status, body = get(f"{base}/readyz")
        assert status == 503
        assert json.loads(body)["status"] == "starting"

    def test_readyz_turns_green_after_an_audit(self, server) -> None:
        base, _, scheduler = server
        scheduler.run_once()
        status, body = get(f"{base}/readyz")
        assert status == 200
        assert json.loads(body)["status"] == "ready"

    def test_readyz_reports_stale_when_the_audit_thread_wedges(self, server) -> None:
        """Staleness is how an operator learns the background thread died."""
        base, cache, scheduler = server
        scheduler.run_once()
        # Backdate the cache beyond 3x the refresh interval.
        with cache._lock:
            cache._updated_at = time.time() - 1000
        status, body = get(f"{base}/readyz")
        assert status == 503
        assert json.loads(body)["status"] == "stale"


class TestMetricsEndpoint:
    def test_503_before_the_first_audit(self, server) -> None:
        base, _, _ = server
        status, _ = get(f"{base}/metrics")
        assert status == 503

    def test_serves_exposition_after_an_audit(self, server) -> None:
        base, _, scheduler = server
        scheduler.run_once()
        status, body = get(f"{base}/metrics")
        assert status == 200
        assert "hardening_agent_check_status" in body
        assert "always_passes" in body

    def test_includes_exporter_self_metrics(self, server) -> None:
        base, _, scheduler = server
        scheduler.run_once()
        _, body = get(f"{base}/metrics")
        assert "hardening_agent_exporter_runs_total 1" in body
        assert "hardening_agent_exporter_metrics_age_seconds" in body

    def test_content_type_is_the_prometheus_type(self, server) -> None:
        base, _, scheduler = server
        scheduler.run_once()
        headers = get_headers(f"{base}/metrics")
        assert headers["Content-Type"].startswith("text/plain")
        assert headers["X-Content-Type-Options"] == "nosniff"

    def test_scrape_does_not_trigger_an_audit(self, server) -> None:
        """Serving from cache is what keeps a scrape from blocking for seconds."""
        base, _, scheduler = server
        scheduler.run_once()
        get(f"{base}/metrics")
        _, second = get(f"{base}/metrics")
        runs = [
            line
            for line in second.splitlines()
            if line.startswith("hardening_agent_exporter_runs_total")
        ]
        assert runs == ["hardening_agent_exporter_runs_total 1"]


class TestRouting:
    def test_unknown_path_is_404(self, server) -> None:
        base, _, _ = server
        status, _ = get(f"{base}/admin")
        assert status == 404

    def test_index_lists_endpoints(self, server) -> None:
        base, _, _ = server
        status, body = get(f"{base}/")
        assert status == 200
        assert "/metrics" in body

    def test_trailing_slash_tolerated(self, server) -> None:
        base, _, _ = server
        assert get(f"{base}/healthz/")[0] == 200

    def test_query_string_ignored(self, server) -> None:
        base, _, _ = server
        assert get(f"{base}/healthz?foo=bar")[0] == 200

    def test_mutating_methods_rejected(self, server) -> None:
        """The exporter is strictly read-only; no endpoint may accept a write."""
        base, _, _ = server
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(  # noqa: S310
                _request(f"{base}/metrics", method="POST", data=b"x"), timeout=5
            )
        assert exc.value.code == 405
        exc.value.close()

    def test_server_version_does_not_leak_python_version(self, server) -> None:
        base, _, _ = server
        assert "Python" not in get_headers(f"{base}/healthz").get("Server", "")


class TestScheduler:
    def test_run_once_publishes_to_the_cache(self, config: Config, runner: AuditRunner) -> None:
        cache = MetricsCache()
        assert not cache.ready
        AuditScheduler(runner, config, cache).run_once()
        assert cache.ready
        rendered, _, runs, errors, _ = cache.snapshot()
        assert runs == 1
        assert errors == 0
        assert "hardening_agent_compliance_score" in rendered

    def test_audit_failure_is_recorded_not_raised(
        self, config: Config, monkeypatch, runner: AuditRunner
    ) -> None:
        """The scheduler thread must never die; a dead thread stops all metrics."""
        cache = MetricsCache()
        scheduler = AuditScheduler(runner, config, cache)
        monkeypatch.setattr(runner, "run", lambda **_: (_ for _ in ()).throw(RuntimeError("boom")))
        scheduler.run_once()
        _, _, runs, errors, last_error = cache.snapshot()
        assert runs == 0
        assert errors == 1
        assert "boom" in (last_error or "")

    def test_start_and_stop_are_clean(self, config: Config, runner: AuditRunner) -> None:
        cache = MetricsCache()
        scheduler = AuditScheduler(runner, config, cache)
        scheduler.start()
        scheduler.stop(timeout=5)
        assert cache.ready

    def test_double_start_is_rejected(self, config: Config, runner: AuditRunner) -> None:
        scheduler = AuditScheduler(runner, config, MetricsCache())
        scheduler.start()
        try:
            with pytest.raises(RuntimeError, match="already started"):
                scheduler.start()
        finally:
            scheduler.stop(timeout=5)
