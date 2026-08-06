# Examples

| File | What it is |
| --- | --- |
| [`prometheus.yml`](prometheus.yml) | Prometheus config for the compose demo stack |
| [`alert_rules.yml`](alert_rules.yml) | Production-shaped alerting rules |
| [`sample-report.json`](sample-report.json) | Illustrative `--format json` output |
| [`agent.production.toml`](agent.production.toml) | A tuned config for a real fleet |

## Running the demo

```bash
docker compose up --build -d

open http://localhost:9090          # Prometheus
curl -s localhost:9101/metrics      # the agent
curl -s localhost:9100/metrics      # node_exporter (textfile path)
```

Try these in the Prometheus expression browser:

```promql
hardening_agent_check_status == 0
hardening_agent_compliance_score
topk(5, hardening_agent_check_duration_seconds)
```

Tear down with `docker compose down -v`.

## The two publication paths

The demo runs both deliberately so you can see the difference:

- **`agent:9101`** — the agent's own HTTP exporter. A dedicated scrape target.
- **`node-exporter:9100`** — the same compliance metrics arriving through the
  textfile collector, which is how you would run this on a host that already has
  node_exporter.

In production you would pick one. See
[docs/metrics.md](../docs/metrics.md#two-publication-paths).

## Alert rule design

The rules in `alert_rules.yml` follow four principles worth stealing:

1. **Alert on severity, not count.** "3 checks failing" is not actionable.
2. **Separate agent problems from host problems.** `HardeningAgentCheckErrored`
   pages the team that owns the agent; `CriticalSecurityControlFailing` pages
   security.
3. **Alert on the transition.** `ComplianceRegression` fires when a control that
   was passing an hour ago starts failing — far more actionable than the steady
   state, because something *changed*.
4. **Detect the silent failure.** `HardeningAgentExporterWedged` catches an
   exporter that is up and responding but serving stale data. Without it, a dead
   audit thread looks perfectly healthy.

Load them into a real Prometheus:

```bash
cp alert_rules.yml /etc/prometheus/
promtool check rules /etc/prometheus/alert_rules.yml
curl -X POST http://localhost:9090/-/reload
```
