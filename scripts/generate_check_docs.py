#!/usr/bin/env python3
"""Generate docs/checks.md from the live check registry.

Hand-written catalogue documentation drifts from the code the first time someone
adds a check and forgets the docs. Generating it means the document is always
accurate, and CI can assert it is up to date with:

    python scripts/generate_check_docs.py --check

Usage:
    python scripts/generate_check_docs.py            # write docs/checks.md
    python scripts/generate_check_docs.py --check    # exit 1 if out of date
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Allow running from a source checkout without installing the package first.
sys.path.insert(0, str(REPO_ROOT / "src"))

from hardening_agent import __version__
from hardening_agent.models import Severity
from hardening_agent.registry import CheckRegistry

OUTPUT_PATH = REPO_ROOT / "docs" / "checks.md"

FAMILY_TITLES = {
    "ssh": "SSH (OpenSSH server)",
    "kernel": "Kernel and network stack (sysctl)",
    "filesystem": "Filesystem permissions and layout",
    "accounts": "User accounts and authentication",
    "services": "Host services (firewall, auditing, patching, time)",
}

FAMILY_ORDER = ["ssh", "kernel", "filesystem", "accounts", "services"]


def family_of(tags: list[str]) -> str:
    """Assign a check to a documentation section by its primary tag."""
    for family in FAMILY_ORDER:
        if family in tags:
            return family
    return "other"


def render() -> str:
    registry = CheckRegistry.with_defaults()
    catalogue = registry.catalogue()

    by_family: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in catalogue:
        by_family[family_of(list(entry["tags"]))].append(entry)  # type: ignore[arg-type]

    histogram = registry.severity_histogram()
    remediable = sum(1 for e in catalogue if e["remediable"])
    risky = sum(1 for e in catalogue if e["risky_remediation"])

    lines: list[str] = []
    add = lines.append

    add("# Check catalogue")
    add("")
    add(
        "> **Generated file.** Produced by `scripts/generate_check_docs.py` from the "
        "live registry. Do not edit by hand; edit the check's `CheckMetadata` and "
        "regenerate."
    )
    add("")
    add(f"`hardening-agent` {__version__} ships **{len(catalogue)} controls**.")
    add("")
    add("| | Count |")
    add("| --- | ---: |")
    add(f"| Total controls | {len(catalogue)} |")
    for severity in reversed(list(Severity)):
        add(f"| {severity.value.capitalize()} severity | {histogram[severity.value]} |")
    add(f"| Remediable | {remediable} |")
    add(f"| ...of which flagged risky | {risky} |")
    add(f"| Audit-only by design | {len(catalogue) - remediable} |")
    add("")
    add("## Reading this document")
    add("")
    add(
        "**Severity** is the impact of the control *failing*, not the difficulty of "
        "fixing it. `fail_on_severity` in the config gates the exit code on it."
    )
    add("")
    add(
        "**Remediable** means the agent can fix it. **Risky** means the fix can sever "
        "your access to the host and requires `--allow-risky` on top of `--yes`."
    )
    add("")
    add(
        "**Rationale** states the actual attack the control prevents. A control "
        "nobody can justify is a control nobody will keep enabled."
    )
    add("")

    for family in [*FAMILY_ORDER, "other"]:
        entries = by_family.get(family)
        if not entries:
            continue
        add(f"## {FAMILY_TITLES.get(family, family.capitalize())}")
        add("")
        add(f"{len(entries)} control(s).")
        add("")

        for entry in entries:
            flag = "audit-only"
            if entry["remediable"]:
                flag = "remediable (risky)" if entry["risky_remediation"] else "remediable"
            add(f"### `{entry['check_id']}`")
            add("")
            add(f"**{entry['title']}**")
            add("")
            add("| | |")
            add("| --- | --- |")
            add(f"| Severity | `{entry['severity']}` |")
            add(f"| Remediation | {flag} |")
            add(f"| Tags | {', '.join(f'`{t}`' for t in entry['tags'])} |")  # type: ignore[union-attr]
            if entry["references"]:
                add(f"| References | {', '.join(entry['references'])} |")  # type: ignore[arg-type]
            add("")
            add(f"{entry['description']}")
            add("")
            add(f"*Why it matters:* {entry['rationale']}")
            add("")

    add("## Running a subset")
    add("")
    add("```bash")
    add("# One family")
    add("hardening-agent audit --tag ssh")
    add("")
    add("# Only the controls that would fail a pipeline")
    add("hardening-agent audit --min-severity high")
    add("")
    add("# One control, with full evidence")
    add("hardening-agent audit --check ssh_root_login_disabled --verbose")
    add("")
    add("# Everything except one that does not apply to this host")
    add("hardening-agent audit --exclude kernel_ip_forwarding_disabled")
    add("```")
    add("")
    add("Available tags:")
    add("")
    add(" ".join(f"`{tag}`" for tag in registry.all_tags()))
    add("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the generated file differs from the committed one",
    )
    args = parser.parse_args()

    generated = render()

    if args.check:
        if not OUTPUT_PATH.exists():
            print(f"{OUTPUT_PATH} does not exist; run this script without --check")
            return 1
        current = OUTPUT_PATH.read_text(encoding="utf-8")
        if current != generated:
            print(f"{OUTPUT_PATH} is out of date.\nRun: python scripts/generate_check_docs.py")
            return 1
        print(f"{OUTPUT_PATH} is up to date.")
        return 0

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT_PATH} ({len(generated.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
