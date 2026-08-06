## What changed

<!-- One or two sentences. What does this do that the codebase did not do before? -->

## Why

<!-- The problem being solved. For a new check, state the ATTACK it prevents --
     reviewers assess that first. "CIS recommends it" is not a rationale. -->

## How it was verified

<!-- Not "tests pass" -- what did you actually run, and against what?
     e.g. "make check green; audited an Ubuntu 24.04 EC2 instance and confirmed
     the check fails before the fix and passes after" -->

---

## Checklist

- [ ] `make check` passes locally
- [ ] New behaviour has tests that would fail without the change
- [ ] No new runtime dependencies (open an issue first if you think you need one)
- [ ] All host access goes through `SystemInterface`

**If this adds or changes a check:**

- [ ] `rationale` names a concrete attack, not a standard
- [ ] `severity` reflects the impact of the control *failing*, not fix difficulty
- [ ] Inapplicable hosts get `SKIP`, never `FAIL`
- [ ] Unreadable evidence gets `SKIP`/`ERROR`, never `PASS`
- [ ] `evidence` makes the report self-explanatory without re-running the agent
- [ ] Registered in the module's `CHECKS` tuple
- [ ] `python scripts/generate_check_docs.py` run and committed

**If this adds or changes a remediation:**

- [ ] `--dry-run` returns before any write
- [ ] Every modified file is backed up first
- [ ] Validated before activation, where a validator exists
- [ ] `risky_remediation=True` if it can sever access to the host
- [ ] Operations ordered so a partial failure is safe
- [ ] A test asserts the rollback path

**If this changes metrics:**

- [ ] No unbounded or state-carrying label values (see docs/metrics.md)
- [ ] Zero-valued series are still emitted so alerts resolve rather than go silent
- [ ] `docs/metrics.md` updated

## Risk

<!-- What could this break in production? How would you notice? How would you
     roll it back? "None" is a valid answer if it is true. -->
