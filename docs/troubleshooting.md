# Troubleshooting

Organised by symptom. Each entry states the likely cause and how to confirm it
before changing anything.

## Diagnosis first

```bash
hardening-agent --version
hardening-agent config                       # effective config AND its source
hardening-agent audit --log-level DEBUG -v   # everything
systemctl status hardening-agent-exporter hardening-agent.timer
journalctl -u hardening-agent-exporter -n 100 --no-pager
curl -s localhost:9101/readyz | jq
```

`hardening-agent config` is the first command to run for anything
configuration-shaped: it prints the effective values **and** which file they came
from, which immediately settles "is it even reading my config?"

---

## Installation

### `python 3.13 or newer is required but was not found`

```bash
sudo apt-get update && sudo apt-get install -y python3.13 python3.13-venv
python3.13 --version
```

On Ubuntu 22.04 and older, 3.13 is not in the default repositories:

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update && sudo apt-get install -y python3.13 python3.13-venv
```

### `failed to create virtualenv`

Almost always the missing `venv` module, which Debian/Ubuntu package separately:

```bash
python3.13 -c 'import venv' || sudo apt-get install -y python3.13-venv
```

### `unsupported distribution`

The checks are written for Debian/Ubuntu. To proceed anyway:

```bash
sudo FORCE_INSTALL=1 ./scripts/install.sh
```

Kernel, filesystem and account checks work on any Linux. `apt`-based checks will
report `SKIP`.

### `/bin/bash^M: bad interpreter`

The scripts were checked out with CRLF line endings. `.gitattributes` prevents
this, but if the repo was copied through Windows without git:

```bash
sed -i 's/\r$//' scripts/*.sh scripts/lib/*.sh
```

---

## Running an audit

### Everything reports `SKIP`

Expected if you are not on Linux, or are inside a container without host mounts.

```bash
hardening-agent audit --format json | jq -r '.results[] | select(.status=="skip") | "\(.check_id): \(.detail)"'
```

The `detail` field says exactly why each one skipped. In a container, add
`--root /host` and the read-only bind mounts (see
[deployment.md](deployment.md#2-container)).

### Credential checks skip with "requires root"

`/etc/shadow` is not readable unprivileged. Run with `sudo`. The agent degrades
to `SKIP` rather than `FAIL` here on purpose — "I could not look" is not the same
as "it is misconfigured".

### A check reports `ERROR`

This is a bug in the agent, not a problem with the host. The report tells you
which check and which exception:

```bash
hardening-agent audit --format json | jq '.results[] | select(.status=="error")'
hardening-agent audit --check <the_id> --log-level DEBUG -v
```

Please open an issue with that output. Exit code 2 exists specifically so
pipelines treat this differently from a finding.

### `unknown check id`

```bash
hardening-agent list-checks | grep -i ssh
```

Typos in `include`/`exclude` are fatal by design — a silently-ignored exclusion
means you believe a control is being skipped when it is not.

### `unknown configuration key(s)`

Also deliberate. A typo'd `fail_on_severty` would silently leave your CI gate
inactive while you believed it was on.

```bash
hardening-agent config          # shows valid keys in context
diff /etc/hardening-agent/agent.toml /etc/hardening-agent/agent.toml.dist
```

### The audit is slow

```bash
hardening-agent audit --format json | jq -r '.results | sort_by(-.duration_ms) | .[:5] | .[] | "\(.duration_ms)ms \(.check_id)"'
```

Usual culprits:

- `services_no_pending_security_updates` runs `apt-get --just-print upgrade`,
  which can take seconds on a host with stale package lists. It is read-only and
  installs nothing.
- `fs_no_world_writable_in_etc` scans `/etc` two levels deep.

Exclude either if the cost is not worth it on your fleet.

---

## Remediation

### `refusing to modify the host without --yes`

Working as intended. Preview first:

```bash
hardening-agent remediate --dry-run --verbose
sudo hardening-agent remediate --yes
```

### A remediation reports `skipped: ... re-run with --allow-risky`

The control's fix can sever your access — enabling a default-deny firewall,
disabling SSH password authentication, locking an account.

**Before overriding, confirm you have a second way in** (EC2 Serial Console,
IPMI, a cloud console session).

```bash
sudo hardening-agent remediate --yes --allow-risky --check ssh_password_auth_disabled
```

Do risky remediations one control at a time.

### A remediation reports `rolled_back`

The safety machinery worked. For SSH this means `sshd -t` rejected the resulting
config and the original was restored before any reload.

```bash
sudo sshd -t                                  # see the actual error
ls -lt /var/backups/hardening-agent/          # the backup set
cat /var/backups/hardening-agent/<id>/manifest.json
```

The most common cause is a pre-existing syntax error elsewhere in
`sshd_config` — the agent's edit merely surfaced it.

### Undoing a remediation

Every modified file was copied first:

```bash
ls -lt /var/backups/hardening-agent/
cat /var/backups/hardening-agent/20260806T101500Z-a1b2c3/manifest.json

# The layout preserves original paths, so plain cp works:
sudo cp /var/backups/hardening-agent/<id>/files/etc/ssh/sshd_config /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
```

The manifest records exactly which files were touched. Entries with an empty
value mean the file did **not** exist before — remove it rather than restoring.

### I locked myself out of SSH

1. Get console access (EC2 Serial Console, cloud provider console, IPMI).
2. Restore from the newest backup set as above.
3. `sshd -t` then `systemctl reload ssh`.

If `--allow-risky` disabled password authentication and you have no key, console
access is the only route. This is why the gate exists.

---

## Metrics and the exporter

### `/metrics` returns 503

No audit has completed yet. Normal for the first ~seconds after start.

```bash
curl -s localhost:9101/readyz | jq
journalctl -u hardening-agent-exporter -n 50
```

If it persists, the audit thread is failing. Check
`hardening_agent_exporter_errors_total` and the logs.

### `/readyz` returns `"status": "stale"`

The cached audit is older than three refresh intervals — the background thread
has wedged or is failing repeatedly.

```bash
curl -s localhost:9101/readyz | jq       # includes last_error
journalctl -u hardening-agent-exporter --since '30 min ago' | grep -i error
sudo systemctl restart hardening-agent-exporter
```

### Prometheus shows no `hardening_agent_*` series

Work outward from the agent:

```bash
curl -s localhost:9101/metrics | head          # 1. is the agent producing?
curl -s localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="hardening-agent")'
```

If the target is down with a connection error, the exporter is bound to loopback
and Prometheus is remote. Set `exporter.host = "0.0.0.0"` **and** restrict port
9101 in your security group to the Prometheus host.

### node_exporter is not picking up the textfile

```bash
ls -l /var/lib/hardening-agent/textfile/
sudo systemctl start hardening-agent.service     # force a write
ps aux | grep node_exporter | grep textfile      # is the flag set?
curl -s localhost:9100/metrics | grep node_textfile_scrape_error
```

`node_textfile_scrape_error 1` means node_exporter could not parse a file in that
directory. Check for a stray non-`.prom` file, and confirm node_exporter can read
the directory (it usually runs as its own user).

The agent writes atomically, so a torn read is not the cause.

### A metric disappeared after a check started passing

It should not — `hardening_agent_check_status` reports `1` for pass, it does not
stop being emitted. If a series genuinely vanished, the check is no longer being
*selected*: check `include`/`exclude`/`min_severity`/`tags` in your config.

```bash
hardening-agent config
hardening-agent list-checks | wc -l
```

---

## systemd

### The timer never fires

```bash
systemctl list-timers hardening-agent.timer
systemctl is-enabled hardening-agent.timer || sudo systemctl enable --now hardening-agent.timer
```

`RandomizedDelaySec=300` means the run happens up to 5 minutes after the hour —
that is deliberate load-spreading across a fleet, not a fault.

### The exporter restart-loops

```bash
journalctl -u hardening-agent-exporter -n 100 --no-pager
```

`StartLimitBurst=5` in 5 minutes stops the loop and leaves the unit failed, so
the problem is visible rather than hidden. After fixing:

```bash
sudo systemctl reset-failed hardening-agent-exporter
sudo systemctl start hardening-agent-exporter
```

Common causes: port 9101 already bound (`ss -lntp 'sport = :9101'`), or an
invalid `agent.toml` (`hardening-agent config`).

### Permission denied writing the textfile

`ProtectSystem=strict` means only `ReadWritePaths` are writable. If you changed
`metrics.textfile_dir`, add the new path to the unit:

```bash
sudo systemctl edit hardening-agent.service
```

```ini
[Service]
ReadWritePaths=/var/lib/hardening-agent /your/new/path
```

### The unit stops slowly

It should stop in milliseconds — the agent handles SIGTERM by draining the audit
thread and closing the socket. If it takes the full `TimeoutStopSec=30`, the
signal handler is not being reached; capture `journalctl -u
hardening-agent-exporter` around the stop and open an issue.

---

## Container

### Metrics describe the container, not the host

The `--root /host` flag is missing.

```bash
docker run ... hardening-agent:local serve --root /host
```

Confirm with `hardening_agent_host_info` — `os_version` should be the host's.

### `read-only file system` in the container

The compose file sets `read_only: true`. That is correct; the agent only needs
`/tmp` (provided as a tmpfs) and its textfile volume. If you changed
`metrics.textfile_dir`, mount a writable volume there.

### Container is unhealthy

The healthcheck polls `/readyz`, which needs the first audit to finish.
`start_period: 20s` covers that. If it stays unhealthy:

```bash
docker logs hardening-agent
docker exec hardening-agent curl -s localhost:9101/readyz
```

---

## Development

### `pytest` fails with `PytestUnraisableExceptionWarning: socket`

A keep-alive socket outlived its test. The test client sends
`Connection: close` for exactly this reason — if you added a request that bypasses
the `get()` helper in `tests/test_exporter.py`, route it through `_request()`.

### `ruff check` flags `/tmp` paths as `S108`

Suppressed globally in `pyproject.toml`. Inspecting `/tmp` permissions is this
project's purpose; the rule fires on ~30 correct lines and zero real defects.

### `docs/checks.md is out of date`

It is generated:

```bash
python scripts/generate_check_docs.py
```

### A new check raises `TypeError: ... must define a metadata class attribute`

Working as intended. Either add `metadata`, or if it is an abstract family base,
declare it as one:

```python
class MyFamily(Check, family=True):
    ...
```

---

## Getting help

Include this in any issue:

```bash
hardening-agent --version
hardening-agent config --format json
hardening-agent audit --format json --log-level DEBUG 2> agent-debug.log
uname -a && cat /etc/os-release
```

Review `agent-debug.log` before attaching it — with `--verbose`, evidence fields
can include configuration values from your host.
