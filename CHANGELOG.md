# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.0.0] - 2026-08-06

First production release.

### Added

**Check catalogue — 40 controls across five families**

- SSH (8): root login, password authentication, empty passwords, X11 forwarding,
  `MaxAuthTries`, idle timeout, `sshd_config` permissions, private host key
  permissions.
- Kernel/sysctl (13): IP forwarding, ICMP redirects (send and accept), source
  routing, reverse path filtering, SYN cookies, ASLR, `kptr_restrict`,
  `dmesg_restrict`, unprivileged eBPF, setuid core dumps, protected hardlinks and
  symlinks.
- Filesystem (9): `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`,
  `/etc/crontab`, `/etc/sudoers` permissions; sticky bits on shared temp
  directories; separate `/tmp` mount options; world-writable files in `/etc`.
- Accounts (5): single UID 0, empty passwords, password expiry policy, system
  account shells, `/root` permissions.
- Services (5): host firewall default-deny, auditd, unattended security upgrades,
  pending security updates, time synchronisation.

Every control carries a severity, a rationale naming the attack it prevents, and
CIS/NIST references.

**Audit and remediation**

- Read-only audit by default; nothing is written unless explicitly requested.
- Opt-in remediation with a seven-layer safety design: `--yes` required,
  `--dry-run` preview, root required, `--allow-risky` for access-severing fixes,
  automatic backup of every modified file, `sshd -t` validation with rollback,
  and a re-audit after remediation so the report reflects reality.
- Timestamped backup sets with a JSON manifest, preserving original paths so a
  human can restore with `cp` if the agent itself is broken.
- Per-check error isolation: one broken check reports `ERROR` and never aborts
  the run.
- `SKIP` distinguished from `FAIL` throughout, with context-aware exceptions
  (container hosts are not flagged for enabling `ip_forward`).

**Observability**

- Prometheus textfile collector with atomic writes for node_exporter.
- HTTP exporter on `:9101` with `/metrics`, `/healthz` and `/readyz`, serving a
  cached audit from a background thread so scrapes never block.
- Staleness detection: `/readyz` returns 503 once the cache exceeds three refresh
  intervals, and `hardening_agent_exporter_metrics_age_seconds` is always
  exported.
- Host telemetry from `/proc`: uptime, load, memory, CPU (as counters), per-mount
  disk capacity, file descriptors, process count.
- Hand-rolled Prometheus exposition rendering with correct label/HELP escaping
  and non-finite float handling.

**Interfaces**

- `audit`, `remediate`, `export`, `serve`, `list-checks`, `config` subcommands.
- Output as text (TTY-aware colour, `NO_COLOR` honoured), JSON (schema-versioned)
  and SARIF 2.1.0 for GitHub code scanning.
- Stable exit-code contract: `0` clean, `1` findings at/above threshold, `2` a
  check errored, `3` usage error.
- Structured JSON logging to stderr, keeping stdout clean for
  `--format json | jq`.

**Configuration**

- TOML parsed with stdlib `tomllib`. Precedence: defaults < file < environment <
  CLI flags.
- Unknown keys are a fatal error — a typo'd security setting must never be
  silently ignored.

**Deployment**

- `install.sh` / `uninstall.sh` / `preflight.sh` / `collect_metrics.sh`.
- systemd service, timer and exporter units with extensive sandboxing
  (`ProtectSystem=strict`, `NoNewPrivileges`, `SystemCallFilter`,
  `MemoryDenyWriteExecute`, resource caps).
- Multi-stage Dockerfile producing a non-root image under the 200 MB budget.
- docker-compose demo stack with Prometheus and node_exporter.

**Quality**

- 378 tests against an in-memory fake host, so the full check suite is validated
  on any platform without root or a VM.
- `mypy --strict`, ruff (including bandit rules), shellcheck.
- CI: lint, typecheck, tests on Ubuntu and macOS, self-audit of the runner,
  container build with size and non-root assertions, graceful-shutdown timing
  test, Trivy and Gitleaks scans, and a full install/uninstall end-to-end job.
- `docs/checks.md` generated from the live registry so it cannot drift.

### Design decisions

- **Zero runtime dependencies.** This process runs as root on every host in a
  fleet; every dependency is a fleet-wide patching obligation and a supply-chain
  path into the root context. Config uses stdlib `tomllib`, metrics are rendered
  by hand, the exporter is `http.server`.
- **One seam to the OS.** All host access goes through `SystemInterface`, which
  is what makes the check suite testable, the subprocess safety reviewable in one
  file, and container host-inspection a single flag.
- **Check status is a numeric gauge, not a label.** Encoding status as a label
  value creates a new time series on every state change and leaves stale series
  reporting the old state indefinitely.
- **Some controls are deliberately not remediable.** Editing fstab, deleting
  accounts, installing updates, and recursive backup deletion are more dangerous
  automated than the findings they address.

### Known limitations

- Ubuntu/Debian focused. Kernel, filesystem and account checks work on any Linux;
  `apt`-based checks report `SKIP` elsewhere.
- `Match` blocks in `sshd_config` are ignored — options inside them are
  conditional on the connection and cannot be evaluated statically. Global values
  are reported, which is the conservative reading.
- The `/etc` world-writable scan is bounded to two directory levels.
- Backup pruning identifies stale sets but does not delete them.
- Several checks cannot be answered from inside a container and report `SKIP`
  (systemd units, firewall tooling, host mount layout).

[Unreleased]: https://github.com/example/linux-hardening-agent/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/example/linux-hardening-agent/releases/tag/v1.0.0
