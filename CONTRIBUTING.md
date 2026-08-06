# Contributing

## Setup

```bash
git clone https://github.com/example/linux-hardening-agent.git
cd linux-hardening-agent
make install
make check      # exactly what CI runs
```

Requires Python 3.13+. `uv` is used if present, `pip` otherwise.

Optional but recommended:

```bash
pre-commit install
```

## The gate

`make check` runs format, lint, typecheck and tests. CI runs the same thing plus
container, shell, security and end-to-end install jobs. A green `make check`
means a green pipeline for the Python side.

| Command | Enforces |
| --- | --- |
| `make fmt` | ruff format |
| `make lint` | ruff check, including bandit security rules |
| `make typecheck` | mypy `--strict` on `src/` |
| `make test` | pytest, 80% coverage floor |
| `make shellcheck` | shellcheck on all scripts |

Non-negotiables: **mypy --strict passes**, **no new runtime dependencies**,
**every check has a rationale**.

## Adding a check

This is the most common contribution. Most controls are five lines.

### 1. Pick the family

Roughly 70% of a CIS-style baseline is three shapes. If yours matches one, use
the base class — the tricky parsing is already written and tested.

| Base class | For |
| --- | --- |
| `SysctlCheck` | "this kernel parameter must equal X" |
| `FilePermissionCheck` | "this file must be no looser than mode Y, owned by Z" |
| `SSHOptionCheck` | "this sshd option must be one of Z" |
| `Check` | Anything else — implement `audit` yourself |

### 2. Write it

```python
# src/hardening_agent/checks/kernel.py

class TCPTimestampsCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_tcp_timestamps_disabled",
        title="TCP timestamps are disabled",
        description="net.ipv4.tcp_timestamps must be 0.",
        severity=Severity.LOW,
        rationale=(
            "TCP timestamps expose the host's uptime and boot time, which lets "
            "an attacker infer the patch level and identify hosts that have not "
            "rebooted since a kernel CVE was disclosed."
        ),
        tags=NET_TAGS | {"information-disclosure"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.3.x",),
    )
    sysctl_key = "net.ipv4.tcp_timestamps"
    expected = "0"
```

### 3. Register it

Add the class to the `CHECKS` tuple at the bottom of the module. Registration is
explicit on purpose — auto-discovery means a half-finished file can silently
change the posture reported for a fleet.

### 4. Test it

```python
class TestTCPTimestamps:
    def test_disabled_passes(self, fake_system, make_context):
        fake_system.sysctl("net.ipv4.tcp_timestamps", "0")
        assert TCPTimestampsCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_enabled_fails(self, fake_system, make_context):
        fake_system.sysctl("net.ipv4.tcp_timestamps", "1")
        assert TCPTimestampsCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_absent_key_skips(self, fake_system, make_context):
        assert TCPTimestampsCheck().audit(make_context(fake_system)).status is Status.SKIP
```

`FakeSystem` (in `tests/conftest.py`) is an in-memory host. You never need a VM,
root, or a real Linux box to test a check.

### 5. Regenerate the catalogue doc

```bash
python scripts/generate_check_docs.py
```

`docs/checks.md` is generated. Edit `CheckMetadata`, not the markdown.

## What makes a check acceptable

### The rationale must name a real attack

The registry test enforces a minimum length, but the bar is higher than that.

Bad: *"CIS recommends this."*
Bad: *"It is more secure."*
Good: *"Accepting ICMP redirects allows an attacker on the local segment to
rewrite this host's routing table and silently reroute traffic through a machine
they control."*

If you cannot state the attack, the control probably should not be in the
baseline. Operators disable controls they cannot justify, and every disabled
control erodes trust in the whole tool.

### Severity is impact, not difficulty

Severity describes what happens when the control **fails**, not how hard it is to
fix. `fail_on_severity` gates CI on it, so inflation directly causes alert
fatigue.

| Severity | Bar |
| --- | --- |
| `critical` | Direct unauthenticated access, or trivial privilege escalation to root |
| `high` | Significant weakening of a primary control; likely exploitation path |
| `medium` | Defence in depth; enables an attack in combination with something else |
| `low` | Hygiene, information disclosure, hardening with marginal practical impact |

### Not applicable means SKIP, never FAIL

A container host that enables `ip_forward` for bridge networking is not
misconfigured. An `sshd` check on a host with no `sshd` is not a finding. A
Debian-only check on RHEL is not a failure.

Look at `IPForwardingCheck` for how to detect and skip a legitimate exception.

**False positives are the single fastest way to make a security tool useless.**
Operators learn to ignore it, and the true positives stop working too.

### Missing evidence is not compliance

If a check cannot read what it needs, it reports `SKIP` (not applicable / no
permission) or `ERROR` (something broke) — never `PASS`. A check that reports
`PASS` because it could not look is worse than no check.

### Evidence must make the report self-explanatory

Put the observed values in `Finding` kwargs. Someone reading a report a week later
should not need to re-run the agent to understand what was wrong.

```python
return Finding.failed(
    f"{self.option} = {effective}, expected {self.desired}",
    option=self.option,
    configured=actual,
    effective=effective,
)
```

Never put a credential in evidence.

## Adding a remediation

Higher bar than a check, because it changes a production host.

```python
def remediate(self, ctx: CheckContext) -> RemediationRecord:
    # 1. Dry run returns before any write.
    if ctx.dry_run:
        return RemediationRecord(RemediationOutcome.DRY_RUN, "would ...")

    # 2. Back up before touching anything.
    ctx.backup.backup_file(TARGET)

    # 3. Make the change.
    ctx.system.write_text(TARGET, updated, mode=0o644)

    # 4. Validate. If validation fails, restore and do NOT activate.
    result = ctx.system.run(["validator", "-t"])
    if not result.ok:
        ctx.backup.restore_set()
        return RemediationRecord(RemediationOutcome.ROLLED_BACK, "...")

    return RemediationRecord(RemediationOutcome.APPLIED, "...")
```

Rules:

- `remediable=True` in metadata **and** an overridden `remediate`. A test asserts
  those stay in sync.
- Set `risky_remediation=True` if the change can sever access to the host
  (firewall, SSH auth, account locking). The runner then requires `--allow-risky`.
- Back up before writing. Always.
- Validate before activating, where a validator exists.
- Order operations so a partial failure is safe. `FirewallEnabledCheck` allows
  SSH *before* applying a deny policy — there is a test asserting that ordering.

If the safe automation is not obvious, prefer `remediable=False` and document the
manual fix. Refusing to automate is a legitimate engineering decision.

## Code standards

- **Type everything.** `mypy --strict` on `src/`.
- **All host access through `SystemInterface`.** Do not import `subprocess` or
  call `open()` on a host path anywhere else. That one seam is what makes the
  whole check suite testable.
- **No runtime dependencies.** If you think you need one, open an issue first.
- **Comment the why, not the what.** `# increment counter` is noise;
  `# f_bfree, not f_bavail: reserved root blocks are not "used"` is the reason
  someone does not "fix" it next year.
- **Never let one check abort a run.** The runner isolates exceptions; do not add
  a code path that bypasses it.

## Tests

- Unit tests use `FakeSystem`. No VM, no root, no real Linux.
- Tests touching sockets or subprocesses get `@pytest.mark.integration`.
- Test the *reason* the code is written that way. `test_rolls_back_when_sshd_t_rejects_the_config`
  documents the most important safety property in the codebase — a future
  refactor that breaks it fails loudly.
- Coverage floor is 80%. Meaningful assertions matter more than the number.

```bash
make test-fast                  # unit only
pytest tests/test_checks_ssh.py -v
pytest -k "rollback" -v
```

## Commits and PRs

Conventional Commits:

```
feat(checks): add TCP timestamp disclosure check
fix(exporter): close keep-alive sockets on shutdown
docs(metrics): explain why status is a gauge not a label
```

A PR should state what changed, why, and how you verified it. For a new check,
include the rationale in the description — reviewers assess that first.

Before opening:

```bash
make check
python scripts/generate_check_docs.py
```

## Project layout

```
src/hardening_agent/
  models.py        Domain types. No I/O.
  system.py        THE SEAM. All OS access.
  config.py        TOML + env + flags. Unknown keys fatal.
  registry.py      Selection, dedup, deterministic ordering.
  runner.py        Execution, error isolation, remediation gating.
  metrics.py       Prometheus exposition, hand-rolled.
  reporting.py     text / json / sarif.
  exporter.py      HTTP server, background audits, graceful shutdown.
  checks/
    base.py        Check ABC + the three reusable families.
    ssh.py kernel.py filesystem.py accounts.py services.py
  observability/
    collectors.py  Host telemetry from /proc.
    textfile.py    Atomic .prom writes.
```

Read [docs/architecture.md](docs/architecture.md) before making structural
changes — it records the four decisions the design rests on and what they cost.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
