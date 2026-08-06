# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue.

Email **ahmed.guebsi@enis.tn** with `[SECURITY]` in the subject, or use GitHub's
private vulnerability reporting on this repository.

Include: affected version, a description, reproduction steps, and the impact you
believe it has. You will get an acknowledgement within 72 hours and an assessment
within 7 days. Fixes for confirmed high/critical issues are targeted within 30
days, and you will be credited in the advisory unless you prefer otherwise.

## Threat model

This agent runs **as root on production hosts** and reads the most sensitive
files on them. That makes it a high-value target, and the design reflects it.

### What it protects against

| Threat | Mitigation |
| --- | --- |
| Supply-chain compromise via dependencies | **Zero runtime dependencies.** Nothing but the Python standard library executes in the root context. |
| Command injection | All subprocess calls pass argv as a list. `shell=True` appears nowhere in the codebase. |
| PATH/environment hijacking | Subprocesses get an explicit `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C`, never the inherited environment. |
| Malicious config causing arbitrary behaviour | Config is data-only TOML. No code evaluation, no plugin loading, no `eval`. Unknown keys are fatal. |
| Agent bug destroying a config file | Every write is atomic (temp file + `os.replace`), and every modified file is backed up first. |
| A remediation locking you out | `sshd -t` validation before reload, automatic rollback on failure, `--allow-risky` gate on access-severing changes. |
| Metrics leaking to attackers | Exporter binds `127.0.0.1` by default. Read-only endpoints; all mutating HTTP methods return 405. |
| A compromised agent process | systemd sandboxing: `ProtectSystem=strict`, `NoNewPrivileges`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, restricted address families, memory and CPU caps. |
| Backup files leaking credentials | Backup directory is `0700 root:root`; manifests are `0600`. |
| Denial of service against the exporter | Request timeouts, bounded request size, audit runs on a background thread so a scrape can never block on it. |

### What it explicitly does not protect against

Stating these plainly is part of the threat model:

- **A compromised root account.** If an attacker is already root, they can
  disable, modify, or lie to this agent. It is a detection and hygiene tool, not
  a defence against an active root-level adversary.
- **Kernel-level compromise.** A rootkit can trivially falsify what `/proc` and
  `/etc` report. Every reading this agent takes is only as trustworthy as the
  kernel underneath it.
- **Tampering with its own reports in transit.** There is no signing of reports
  or metrics. Scrape over a trusted network path.
- **Runtime behaviour.** Every control examines *configuration state*. A host
  can be perfectly configured and still be actively compromised.

## Privilege design

### Why it runs as root

The audit must read `/etc/shadow` (password hashes) and `/etc/ssh/ssh_host_*_key`
(private host keys) to answer its most important questions. Running unprivileged
makes every credential-related control report `SKIP`, which is worse than not
running the agent.

`CAP_DAC_READ_SEARCH` was considered as an alternative. It is close to equivalent
to root on a host like this — it grants read access to every file on the system —
while being harder for a reviewer to reason about. The honest position is: it
runs as root, and the systemd sandbox is what constrains the blast radius.

### Reducing privilege where possible

- The **container** image runs as uid 65532 with `cap_drop: ALL`, inspecting the
  host through read-only bind mounts. No write access to the host exists.
- The **installer** creates a `hardening-agent` system account with no shell and
  no home for the state directories, so the metrics path is not root-owned.
- `hardening-agent export` and `serve` never write outside
  `/var/lib/hardening-agent` and `/var/log/hardening-agent`, and the units
  enforce that with `ProtectSystem=strict` + `ReadWritePaths`.

## Handling of sensitive data

**What the agent reads:** `/etc/shadow`, `/etc/gshadow`, `/etc/passwd`,
`/etc/sudoers`, `/etc/ssh/sshd_config`, private host key *metadata*.

**What it never does:**

- Never logs a password hash or private key.
- Never includes file *contents* in a report — only derived facts (mode, owner,
  whether a field was empty).
- Never transmits anything off the host. There is no phone-home, no telemetry,
  no update check.

**Where care is still needed:**

- `--verbose` / `logging.include_evidence` puts evidence fields in logs and
  reports. Evidence contains configuration values and paths — no credentials, but
  enough detail to be worth reviewing before pasting into a public issue.
- Backups under `/var/backups/hardening-agent` contain **verbatim copies** of
  files the agent modified, which can include `/etc/shadow`-adjacent content. The
  directory is `0700 root:root`. Do not copy it to shared storage without
  encryption.
- **Metrics enumerate exactly how the host is weak.** A reachable `/metrics`
  endpoint is a reconnaissance gift. Keep it on loopback, or restrict it at the
  security group / firewall to your Prometheus server only.

## Remediation safety

Remediation is the only part of the agent that changes a host, and it is gated at
seven layers:

1. Audit-only by default; `remediation.enabled = false`.
2. `remediate` refuses without an explicit `--yes`.
3. `--dry-run` previews with zero writes.
4. Non-dry-run remediation requires root.
5. Access-severing fixes additionally require `--allow-risky`.
6. Every file is copied to a timestamped backup set before modification.
7. SSH changes validate with `sshd -t` and roll back automatically on failure.

Controls deliberately left non-remediable, because automating them is more
dangerous than the finding:

- `fs_tmp_separate_partition` — editing fstab can make a host unbootable.
- `accounts_single_uid_zero` — deleting or renumbering accounts automatically.
- `services_no_pending_security_updates` — installing updates restarts services.
- `fs_no_world_writable_in_etc` — the correct mode depends on the file.

Backup **pruning** identifies stale sets but does not delete them. Recursive
removal as root is the single most dangerous operation this codebase could
contain, so it is not implemented in the agent at all.

## Supply chain

- **Zero runtime dependencies** — see above.
- Dev dependencies (ruff, mypy, pytest) never ship to a host.
- Dependabot tracks GitHub Actions, Docker base images, and the dev toolchain.
- CI runs Trivy (filesystem and image), Gitleaks, and ruff's bandit ruleset.
- Release images are built with SLSA provenance attestation and an SBOM, and are
  signed with the workflow's OIDC identity, so consumers can verify an image came
  from this repository's release pipeline.
- Container images are scanned for HIGH/CRITICAL CVEs before publication.

Verify a published image:

```bash
gh attestation verify oci://ghcr.io/example/linux-hardening-agent:1.0.0 \
  --owner example
```

## Hardening the agent's own deployment

```bash
# Confirm the sandbox is active
systemd-analyze security hardening-agent-exporter.service

# Confirm the exporter is not exposed
ss -lntp 'sport = :9101'      # should show 127.0.0.1:9101

# Confirm backup permissions
stat -c '%a %U:%G' /var/backups/hardening-agent    # expect 700 root:root

# Confirm the container is unprivileged
docker inspect hardening-agent --format '{{.Config.User}}'
```

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Scope

**In scope:** command injection, privilege escalation, path traversal, incorrect
check logic that reports a vulnerable host as compliant, remediation that damages
a host, credential exposure in logs/reports/metrics, exporter vulnerabilities.

**Out of scope:** findings that require existing root access; the agent being
disabled by an administrator; missing checks (open a feature request instead);
vulnerabilities in Python itself (report upstream); the exporter being reachable
because an operator bound it to `0.0.0.0` against documented advice.
