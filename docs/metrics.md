# Metrics reference

## Two publication paths

The agent publishes the same data two ways because periodic audits and 15-second
scrapes are different problems.

| | Textfile collector | HTTP exporter |
| --- | --- | --- |
| Mechanism | Writes `*.prom`, node_exporter reads it | Serves `:9101/metrics` |
| Driven by | systemd timer (hourly) | Background thread (60s default) |
| Use when | The host already runs node_exporter | You want a dedicated scrape target |
| Extra process | None | One long-lived Python process |
| Command | `hardening-agent export` | `hardening-agent serve` |

Both are enabled by the installer. Turn either off in `agent.toml`
(`metrics.enabled`, `exporter.enabled`).

### Textfile collector

```bash
# node_exporter must be started with:
node_exporter --collector.textfile.directory=/var/lib/hardening-agent/textfile
```

Writes are atomic — a temporary file in the same directory, `fsync`, then
`os.replace`. If node_exporter catches a half-written file it drops the entire
scrape and logs a parse error, so this matters more than it looks.

### HTTP exporter

| Endpoint | Purpose | Codes |
| --- | --- | --- |
| `GET /metrics` | Prometheus exposition | 200, 503 before the first audit |
| `GET /healthz` | Liveness — is the process up | 200 always |
| `GET /readyz` | Readiness — is the data fresh | 200, 503 starting or stale |
| `GET /` | Endpoint listing | 200 |
| Anything else | | 404 |
| `POST`/`PUT`/`DELETE`/`PATCH` | Rejected; the exporter is read-only | 405 |

`/healthz` deliberately does **not** depend on the audit. If liveness failed
while the first audit was still running, an orchestrator would kill the process
before it ever produced data.

`/readyz` returns 503 when the cached audit is older than three refresh
intervals. That is how a wedged audit thread becomes visible instead of silently
serving stale numbers forever.

**Binding.** Loopback by default. These metrics enumerate exactly how the host is
weak — which is a reconnaissance gift. Expose them only behind a security group
you trust.

## Compliance metrics

### `hardening_agent_check_status`

`gauge` — the outcome of each control.

| Value | Meaning |
| ---: | --- |
| `1` | pass |
| `0` | fail |
| `2` | skip (not applicable to this host) |
| `3` | error (check broke; posture unknown) |

Labels: `check_id`, `severity`, `title`.

```
hardening_agent_check_status{check_id="ssh_root_login_disabled",severity="critical",title="SSH direct root login is disabled"} 0
```

**Why a numeric gauge and not `status="fail"` as a label?** Using the status as a
label value creates a brand-new time series every time a check changes state, and
the old series does not disappear — it goes stale and keeps reporting the old
value for the whole retention window. An alert on `status="fail"` would keep
firing long after the problem was fixed. This is a common and painful Prometheus
modelling mistake.

The unusual encoding (0 = fail, not 1) is chosen so `== 0` reads as "failing"
and `min_over_time` behaves intuitively for pass/fail.

### `hardening_agent_compliance_score`

`gauge` — percentage of *applicable* checks that passed, 0-100.

Skipped and errored checks are excluded from both numerator and denominator.
Counting skips as passes would let a host where nothing applies score 100%.

### `hardening_agent_failed_checks_by_severity`

`gauge` — count of failing checks, labelled `severity`.

All four severities are always emitted, including zeros. A metric that vanishes
when the count hits zero makes alerts go stale-silent rather than resolving.

### `hardening_agent_checks_total`

`gauge` — count by outcome, labelled `status` (`pass`/`fail`/`skip`/`error`).

Note this is a *summary count*, so `status` as a label is correct here — the
label set is fixed and complete, unlike per-check status.

### `hardening_agent_check_duration_seconds`

`gauge` — per-check execution time, labelled `check_id`. Use it to find the check
responsible when audits get slow.

### `hardening_agent_last_run_timestamp_seconds`

`gauge` — Unix timestamp of the last completed audit. The basis of every
staleness alert:

```promql
time() - hardening_agent_last_run_timestamp_seconds > 7200
```

### `hardening_agent_run_duration_seconds`

`gauge` — wall-clock duration of the whole audit.

### `hardening_agent_host_info`

`gauge`, always `1`. An *info metric*: metadata carried as labels
(`hostname`, `os_name`, `os_version`, `kernel`, `architecture`,
`virtualization`, `agent_version`, `profile`).

This is the standard pattern for attaching descriptive data without creating a
series per changing value. Join it onto other metrics:

```promql
hardening_agent_compliance_score * on(instance) group_left(os_version)
  hardening_agent_host_info
```

## Exporter self-observability

| Metric | Type | Meaning |
| --- | --- | --- |
| `hardening_agent_exporter_runs_total` | counter | Audits completed since start |
| `hardening_agent_exporter_errors_total` | counter | Audit runs that raised |
| `hardening_agent_exporter_metrics_age_seconds` | gauge | Age of the cached result |

`metrics_age_seconds` climbing steadily means the background audit thread has
wedged and every other metric is stale. Alert on it.

## Collector health (textfile path only)

Written by `scripts/collect_metrics.sh`, which publishes these **even when the
audit fails**. Without them, a broken agent looks identical to a healthy, silent
one.

| Metric | Meaning |
| --- | --- |
| `hardening_agent_collector_success` | `1` ok, `0` the collection failed |
| `hardening_agent_collector_duration_seconds` | Time taken |

## Host telemetry

Enabled by `metrics.host_metrics`. Deliberately *not* a node_exporter
replacement — just enough context to interpret a compliance report.

| Metric | Type | Labels |
| --- | --- | --- |
| `hardening_agent_host_uptime_seconds` | gauge | |
| `hardening_agent_host_load_average` | gauge | `window` = 1m/5m/15m |
| `hardening_agent_host_memory_bytes` | gauge | `kind` = total/free/available/... |
| `hardening_agent_host_memory_used_percent` | gauge | |
| `hardening_agent_host_cpu_seconds_total` | **counter** | `mode` = user/system/idle/... |
| `hardening_agent_host_cpu_count` | gauge | |
| `hardening_agent_host_filesystem_size_bytes` | gauge | `mountpoint` |
| `hardening_agent_host_filesystem_avail_bytes` | gauge | `mountpoint` |
| `hardening_agent_host_filesystem_used_percent` | gauge | `mountpoint` |
| `hardening_agent_host_file_descriptors_allocated` | gauge | |
| `hardening_agent_host_file_descriptors_max` | gauge | |
| `hardening_agent_host_processes` | gauge | |

**CPU is a counter, not a percentage.** Producing an instantaneous "CPU %" from a
single sample would require sleeping and sampling twice inside the agent.
Prometheus computes it far more accurately from a counter:

```promql
100 - (avg by(instance) (rate(hardening_agent_host_cpu_seconds_total{mode="idle"}[5m])) * 100)
```

## PromQL you will actually use

```promql
# Every currently failing control
hardening_agent_check_status == 0

# Critical failures only
hardening_agent_check_status{severity="critical"} == 0

# Hosts below 90% compliance, worst first
sort(hardening_agent_compliance_score < 90)

# Fleet-wide compliance
avg(hardening_agent_compliance_score)

# Which control fails on the most hosts
topk(10, count by(check_id) (hardening_agent_check_status == 0))

# Checks that are erroring -- these are agent bugs, not host problems
hardening_agent_check_status == 3

# Agents that have stopped reporting
time() - hardening_agent_last_run_timestamp_seconds > 7200

# A control that regressed in the last hour
hardening_agent_check_status == 0
  and (hardening_agent_check_status offset 1h) == 1

# Slowest checks
topk(5, hardening_agent_check_duration_seconds)

# Disk about to fill
hardening_agent_host_filesystem_used_percent > 85
```

## Alerting

Rules ship in [examples/alert_rules.yml](../examples/alert_rules.yml). The design
principles behind them:

**Alert on severity, not on count.** "3 checks failing" is not actionable; "a
critical control is failing on web-01" is.

**Alert on staleness separately.** A missing metric and a failing metric need
different responses — one is an agent problem, the other a host problem.

**Alert on `error` status.** An erroring check is a bug in *this repository*, and
it should page the team that owns the agent, not the team that owns the host.

**Use `for:` generously.** A check failing for 15 minutes during a maintenance
window is noise. A critical control failing for an hour is real.

## Exposition format notes

Rendering is hand-written (`metrics.py`, ~100 lines) rather than using
`prometheus_client`, to keep runtime dependencies at zero — see
[architecture.md](architecture.md).

The implementation handles the parts that bite:

- **Label escaping** — backslash, double quote and newline. Check titles contain
  `/etc/shadow` and quotes; an unescaped newline produces an unparseable payload.
- **HELP escaping** — backslash and newline only, per spec.
- **Non-finite floats** — rendered as `NaN`, `+Inf`, `-Inf`, not Python's `nan`.
- **Sorted label keys** — byte-stable output across runs, so the textfile is
  diffable and does not churn.
- **Trailing newline** — a file without one makes node_exporter drop the scrape.

CI validates that every emitted line parses as `name{labels} value`.
