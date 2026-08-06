# Linux Hardening & Observability Agent

A dependency-free Python agent that audits an Ubuntu/Debian host against a
CIS-derived security baseline, optionally remediates findings with backup and
rollback, and publishes the result as Prometheus metrics.

[![CI](https://github.com/example/linux-hardening-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/example/linux-hardening-agent/actions/workflows/ci.yml)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## What it does

```
$ sudo hardening-agent audit

==============================================================================
 Linux Hardening Report  (1.0.0, profile: baseline)
==============================================================================
 Host        : web-01  [Ubuntu 24.04]
 Kernel      : 6.8.0-41-generic (x86_64, ec2)
 Duration    : 412 ms

 FINDINGS (3)
------------------------------------------------------------------------------
 [CRITICAL] ssh_root_login_disabled
            SSH direct root login is disabled
            -> PermitRootLogin = yes, expected no

 [  HIGH  ] services_unattended_upgrades_enabled
            Automatic security updates are enabled
            -> /etc/apt/apt.conf.d/20auto-upgrades is missing

 [ MEDIUM ] kernel_tcp_syncookies_enabled
            TCP SYN cookies are enabled
            -> net.ipv4.tcp_syncookies = 0, expected 1

------------------------------------------------------------------------------
 pass=27  fail=3  skip=4  error=0
 Compliance score: 90.0% (of applicable checks)
==============================================================================
```

The same run, as metrics:

```
$ curl -s localhost:9101/metrics | grep hardening_agent_check_status | head -3
hardening_agent_check_status{check_id="ssh_root_login_disabled",severity="critical",title="..."} 0
hardening_agent_check_status{check_id="accounts_single_uid_zero",severity="critical",title="..."} 1
hardening_agent_check_status{check_id="fs_shadow_permissions",severity="critical",title="..."} 1
```

## Design in one paragraph

**Audit-only by default; remediation is opt-in, backed up, validated, and
reversible.** A tool that rewrites `sshd_config` the first time you run it is a
tool nobody runs on a production host. So `audit` never writes anything,
`remediate --dry-run` prints the plan, and `remediate --yes` applies changes only
after copying every file it touches. Remediations that can sever your access —
enabling a default-deny firewall, disabling SSH password auth — are additionally
gated behind `--allow-risky`. SSH changes are validated with `sshd -t` and rolled
back automatically if validation fails.

**Zero runtime dependencies.** This process runs as root. Config is parsed with
stdlib `tomllib`, Prometheus exposition is rendered by hand (~100 lines), and the
HTTP exporter is `http.server`. Nothing to CVE-patch across a fleet, nothing in
`site-packages` inside the root context.

## Install

```bash
git clone https://github.com/example/linux-hardening-agent.git
cd linux-hardening-agent
sudo ./scripts/install.sh
```

The installer creates a dedicated `hardening-agent` system user, installs to
`/opt/hardening-agent`, and enables a systemd timer (hourly audit) plus the
metrics exporter. See [docs/deployment.md](docs/deployment.md).

Uninstall cleanly at any time:

```bash
sudo ./scripts/uninstall.sh          # keeps reports and backups
sudo ./scripts/uninstall.sh --purge  # removes everything
```

### Without installing

```bash
python3.13 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
hardening-agent audit
```

### Container

```bash
docker compose up --build          # agent + Prometheus + node_exporter
open http://localhost:9090         # Prometheus
curl localhost:9101/metrics        # agent
```

The container inspects the host read-only via bind mounts (`/proc`, `/etc`,
`/sys` at `:ro`) and runs as a non-root user.

## Usage

```bash
hardening-agent audit                          # read-only report
hardening-agent audit --format json | jq .     # machine-readable
hardening-agent audit --format sarif -o r.sarif  # GitHub code scanning
hardening-agent audit --verbose                # include passes and evidence
hardening-agent audit --tag ssh --tag kernel   # subset by tag
hardening-agent audit --min-severity high      # only serious controls
hardening-agent audit --fail-on critical       # CI gate threshold

hardening-agent remediate --dry-run            # show the plan, change nothing
sudo hardening-agent remediate --yes           # apply safe remediations
sudo hardening-agent remediate --yes --allow-risky --check ssh_password_auth_disabled

hardening-agent export                         # write the .prom textfile
hardening-agent export --stdout                # print metrics
hardening-agent serve                          # HTTP exporter on :9101

hardening-agent list-checks                    # the catalogue
hardening-agent config                         # effective config + its source
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Compliant — no findings at or above `fail_on_severity` |
| `1`  | Findings at or above the threshold |
| `2`  | A check errored; the host's posture is **unknown** |
| `3`  | Usage or configuration error |

Errors outrank findings deliberately: a broken check means you don't know the
answer, which a pipeline must not treat as merely non-compliant.

## The checks

40 controls across five families. `hardening-agent list-checks` prints the live
catalogue; [docs/checks.md](docs/checks.md) documents each one with its rationale.

| Family | Count | Examples |
| ------ | ----- | -------- |
| SSH | 8 | root login, password auth, host key permissions, `MaxAuthTries` |
| Kernel / sysctl | 13 | ASLR, `rp_filter`, SYN cookies, unprivileged eBPF, `kptr_restrict` |
| Filesystem | 9 | `/etc/shadow` mode, sticky bits, world-writable files in `/etc` |
| Accounts | 5 | single UID 0, empty passwords, system-account shells |
| Services | 5 | firewall default-deny, auditd, unattended-upgrades, time sync |

Every check declares a **severity**, a **rationale** explaining the actual attack
it prevents, and a **CIS/NIST reference**. Checks that don't apply to a host
report `SKIP`, not `FAIL` — a container host that enables `ip_forward` for bridge
networking is not misconfigured, and false positives train people to ignore the
tool.

## Metrics

Published two ways, because periodic audits and 15-second scrapes are different
problems:

- **Textfile collector** — writes `hardening_agent.prom` atomically for
  node_exporter to pick up. Right for a host that already runs node_exporter.
- **HTTP exporter** — `:9101/metrics`, `/healthz`, `/readyz`. Audits run on a
  background thread and serve from a cache, so a scrape never blocks on a
  multi-second audit.

Key series (full reference in [docs/metrics.md](docs/metrics.md)):

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `hardening_agent_check_status` | gauge | `1`=pass `0`=fail `2`=skip `3`=error |
| `hardening_agent_compliance_score` | gauge | % of applicable checks passing |
| `hardening_agent_failed_checks_by_severity` | gauge | failing count per severity |
| `hardening_agent_last_run_timestamp_seconds` | gauge | staleness detection |
| `hardening_agent_exporter_metrics_age_seconds` | gauge | is the audit thread alive |

Status is a numeric gauge rather than a `status="fail"` label on purpose — using
the status as a label creates a new time series on every state change and leaves
stale series reporting the old state forever.

Example alerts ship in [examples/alert_rules.yml](examples/alert_rules.yml).

## Development

```bash
make help          # every target
make install       # venv + editable install + dev deps
make fmt           # ruff format
make lint          # ruff check
make typecheck     # mypy --strict
make test          # pytest with coverage
make check         # everything CI runs
make docker        # build the image
make demo          # compose stack with Prometheus
```

Tests run against an in-memory fake filesystem (`FakeSystem`), so the entire
check suite is validated on any platform without root and without a VM. That is
the payoff of routing all host access through one `SystemInterface` seam.

## Documentation

| Document | Contents |
| -------- | -------- |
| [docs/architecture.md](docs/architecture.md) | Component design, data flow, the decisions and their trade-offs |
| [docs/checks.md](docs/checks.md) | Every control, its rationale and references |
| [docs/metrics.md](docs/metrics.md) | Metric reference, PromQL, alerting |
| [docs/deployment.md](docs/deployment.md) | systemd, container, Ansible, AWS |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Symptom-first runbook |
| [SECURITY.md](SECURITY.md) | Threat model, privilege design, reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add a check |

## Known limitations

- Ubuntu/Debian focused. RHEL-family hosts run the kernel, filesystem and account
  checks correctly; `apt`-based checks report `SKIP`.
- `Match` blocks in `sshd_config` are ignored. Options inside them are
  conditional on the connection and cannot be evaluated statically; the agent
  reports global values only, which is the conservative reading.
- The `/etc` world-writable scan is bounded to two directory levels. A full
  recursive walk as root on every audit is an I/O cost not worth paying on a
  monitored host.
- Backup pruning reports what should be deleted but does not delete it —
  recursive removal as root is not something this codebase will contain.

## License

MIT — see [LICENSE](LICENSE).
