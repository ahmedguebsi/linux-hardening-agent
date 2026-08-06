# Deployment

## Choosing a deployment model

| Model | Use when | Trade-off |
| --- | --- | --- |
| systemd (native) | Long-lived VMs, EC2, bare metal | Needs Python 3.13 on the host |
| Container | Container hosts, k8s nodes, immutable infra | Host inspection via bind mounts |
| Ad-hoc CLI | CI pipelines, golden-image validation | No continuous monitoring |
| Config management | Fleets of any size | Requires Ansible/Chef/Salt |

## 1. systemd (recommended for VMs)

### Requirements

Ubuntu 24.04 or Debian 12, systemd, Python 3.13+.

```bash
sudo apt-get update
sudo apt-get install -y python3.13 python3.13-venv
```

Verify the host first — this is read-only and safe to run anywhere:

```bash
./scripts/preflight.sh
```

### Install

```bash
git clone https://github.com/example/linux-hardening-agent.git
cd linux-hardening-agent
sudo ./scripts/install.sh
```

What it does:

1. Creates the `hardening-agent` system user (no shell, no home).
2. Builds a self-contained venv at `/opt/hardening-agent/venv`.
3. Installs config to `/etc/hardening-agent/agent.toml` — **never overwriting an
   existing one**; on upgrade it writes `agent.toml.dist` alongside instead.
4. Installs and enables `hardening-agent.timer` (hourly) and
   `hardening-agent-exporter.service`.
5. Runs a verification audit.

Flags: `--no-exporter`, `--no-timer`, `--yes`. Env: `FORCE_INSTALL=1` to install
on an unsupported distro.

The installer is **idempotent** — re-running it upgrades in place.

### Layout

| Path | Contents | Mode |
| --- | --- | --- |
| `/opt/hardening-agent/` | venv and helper scripts | 0755 root |
| `/etc/hardening-agent/agent.toml` | Configuration | 0644 root |
| `/var/lib/hardening-agent/textfile/` | `*.prom` for node_exporter | 0755 agent |
| `/var/backups/hardening-agent/` | Remediation backups | **0700 root** |
| `/var/log/hardening-agent/` | Optional log file | 0750 agent |
| `/usr/local/bin/hardening-agent` | Symlink | |

Backups are 0700 root-only because they contain copies of files adjacent to
`/etc/shadow`.

### Operating

```bash
systemctl status hardening-agent.timer
systemctl list-timers hardening-agent.timer     # next scheduled run
journalctl -u hardening-agent-exporter -f       # live logs
journalctl -u hardening-agent --since '1 hour ago'

sudo systemctl start hardening-agent.service    # audit now
curl -s localhost:9101/metrics | grep compliance_score
```

### The units are themselves hardened

A tool that audits hardening should be hardened. Both units set
`ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, `SystemCallFilter=@system-service`,
`MemoryDenyWriteExecute`, and a restricted `RestrictAddressFamilies`. The exporter
additionally caps `MemoryMax=256M` and `CPUQuota=50%`, so a leak becomes a restart
rather than an OOM event that takes the host down.

```bash
systemd-analyze security hardening-agent-exporter.service
```

**Note:** `ProtectSystem=strict` makes `/etc` read-only for these units. That is
fine because they only ever run `export` and `serve`. `hardening-agent remediate`
is a deliberate interactive command run *outside* the units, so it is unaffected.
If you ever add a remediation timer, it needs its own unit with `/etc` in
`ReadWritePaths`.

### Why root?

Both units run as root because the audit must read `/etc/shadow` and private SSH
host keys. The alternative — `CAP_DAC_READ_SEARCH` — is close to equivalent to
root on a host like this, while being harder to reason about. The honest position
is: it runs as root, and the sandbox directives are what constrain the blast
radius. Running unprivileged is possible, but every credential-related control
then reports `SKIP`, which is worse than not running the agent at all.

### Uninstall

```bash
sudo ./scripts/uninstall.sh            # removes software, KEEPS backups
sudo ./scripts/uninstall.sh --purge    # removes everything
```

Backups are kept by default deliberately: they are the only record of what the
agent changed, and deleting them destroys the ability to undo a remediation.

Uninstalling does **not** revert hardening already applied to the host.

## 2. Container

```bash
docker compose up --build -d
curl localhost:9101/metrics
open http://localhost:9090
```

Or standalone:

```bash
docker run -d --name hardening-agent \
  -p 127.0.0.1:9101:9101 \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp \
  ghcr.io/example/linux-hardening-agent:1.0.0 \
  serve --root /host
```

### How host inspection works

`--root /host` makes every read in `SystemInterface` resolve against the bind
mounts. The checks themselves know nothing about it. All mounts are `:ro`, so the
container has **no write access to the host at all** — which is why it can safely
drop every capability and run as an unprivileged user.

### Container limitations

Some checks cannot be answered from inside a container and will `SKIP`:

- `systemctl`-based checks (auditd, time sync) — no access to the host's systemd.
- `ufw`/`nft` checks — the binaries and netlink access are not present.
- `fs_tmp_separate_partition` — the container's mount table is not the host's.
  The compose file excludes it explicitly rather than emitting a false positive
  on every scrape.

Kernel sysctls, file permissions and account checks all work correctly, because
those are readable from `/host/proc` and `/host/etc`.

For full coverage on a container host, run the agent natively via systemd and
scrape it; use the container when the host is immutable and you accept the gaps.

### Image

Multi-stage build: a builder stage with the full toolchain produces a venv, and
the runtime stage copies only that venv into `python:3.13-slim`. No compiler, no
pip cache, no source tree in the final image. Runs as uid 65532.

`make docker-size` asserts the image stays under 200 MB; CI enforces the same
budget.

## 3. CI / golden-image validation

Validate an image at build time and fail the build on regressions:

```yaml
- name: Harden check
  run: |
    pip install hardening-agent
    hardening-agent audit --fail-on high --format json -o report.json
```

Exit codes: `0` clean, `1` findings at/above the threshold, `2` a check errored,
`3` usage error.

Publish to GitHub code scanning:

```yaml
- run: hardening-agent audit --format sarif -o hardening.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: hardening.sarif
```

Packer post-processor:

```json
{
  "type": "shell",
  "inline": [
    "sudo ./scripts/install.sh --yes --no-exporter",
    "sudo hardening-agent remediate --yes",
    "sudo hardening-agent audit --fail-on high"
  ]
}
```

Remediating at image-build time and auditing after is the right order: the image
ships hardened, and the build fails if remediation did not achieve it.

## 4. Ansible

```yaml
- name: Deploy hardening agent
  hosts: linux_servers
  become: true
  tasks:
    - name: Install Python 3.13
      ansible.builtin.apt:
        name: [python3.13, python3.13-venv]
        state: present
        update_cache: true

    - name: Copy agent source
      ansible.builtin.copy:
        src: ../linux-hardening-agent/
        dest: /opt/src/hardening-agent/
        mode: "0755"

    - name: Preflight
      ansible.builtin.command: /opt/src/hardening-agent/scripts/preflight.sh
      changed_when: false
      failed_when: false
      register: preflight

    - name: Install
      ansible.builtin.command: /opt/src/hardening-agent/scripts/install.sh --yes
      args:
        creates: /opt/hardening-agent/venv/bin/hardening-agent
      environment:
        ASSUME_YES: "1"

    - name: Deploy configuration
      ansible.builtin.template:
        src: agent.toml.j2
        dest: /etc/hardening-agent/agent.toml
        mode: "0644"
      notify: restart exporter

    - name: Wait for readiness
      ansible.builtin.uri:
        url: http://127.0.0.1:9101/readyz
        status_code: 200
      retries: 10
      delay: 3

  handlers:
    - name: restart exporter
      ansible.builtin.systemd:
        name: hardening-agent-exporter
        state: restarted
        daemon_reload: true
```

## 5. AWS

### EC2 user data

```bash
#!/bin/bash
set -euo pipefail
apt-get update && apt-get install -y git python3.13 python3.13-venv
git clone https://github.com/example/linux-hardening-agent.git /opt/src/ha
cd /opt/src/ha
ASSUME_YES=1 ./scripts/install.sh --yes
# Remediate at first boot so instances launch compliant.
hardening-agent remediate --yes || true
```

### Prometheus service discovery

```yaml
scrape_configs:
  - job_name: hardening-agent
    ec2_sd_configs:
      - region: eu-west-1
        port: 9101
    relabel_configs:
      - source_labels: [__meta_ec2_tag_Environment]
        target_label: environment
      - source_labels: [__meta_ec2_instance_id]
        target_label: instance_id
      - source_labels: [__meta_ec2_tag_Name]
        target_label: name
```

The exporter binds loopback by default. To scrape across the network, set
`exporter.host = "0.0.0.0"` **and** restrict port 9101 in the security group to
the Prometheus server's security group only. These metrics describe exactly how
each host is weak.

### Security group

```hcl
resource "aws_security_group_rule" "hardening_agent_scrape" {
  type                     = "ingress"
  from_port                = 9101
  to_port                  = 9101
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.prometheus.id
  description              = "Prometheus scrapes hardening-agent metrics"
}
```

## Configuration in production

Point-in-time overrides without editing the file:

```bash
HARDENING_AGENT_PROFILE=pci \
HARDENING_AGENT_MIN_SEVERITY=medium \
HARDENING_AGENT_EXCLUDE=kernel_ip_forwarding_disabled \
  hardening-agent audit
```

Fleet-specific baselines via the `profile` label, which lands in
`hardening_agent_host_info` and lets you compare like with like:

```toml
[audit]
profile = "pci-cardholder-data"
min_severity = "medium"
fail_on_severity = "medium"
```

NAT instances and container hosts legitimately forward packets:

```toml
[audit]
exclude = ["kernel_ip_forwarding_disabled"]
```

## Rollout strategy

Do not enable remediation fleet-wide on day one.

1. **Week 1 — observe.** Deploy audit-only everywhere. Look at the fleet
   compliance score and find which controls fail on the most hosts
   (`topk(10, count by(check_id) (hardening_agent_check_status == 0))`).
2. **Week 2 — dry run.** `hardening-agent remediate --dry-run` on a
   representative host from each role. Read the plan.
3. **Week 3 — canary.** Remediate one non-production host per role. Verify
   nothing broke, especially SSH access from a second terminal *before* closing
   the first.
4. **Week 4 — staged rollout.** Non-production, then production in waves, with
   the compliance score as the success metric.
5. **Risky remediations last, individually.** `--allow-risky` covers firewall
   enablement and SSH password-auth disablement. Do those one control at a time,
   with out-of-band console access available.

**Before any risky remediation, confirm you have a second way into the host.**
EC2 Serial Console, an IPMI/iDRAC session, or a cloud provider's console. The
`--allow-risky` gate exists because these changes can lock you out permanently.
