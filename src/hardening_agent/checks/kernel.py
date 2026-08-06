"""Kernel and network stack controls (sysctl).

All of these read the live value from ``/proc/sys`` and remediate by writing a
drop-in under ``/etc/sysctl.d/`` *and* applying at runtime. See
:class:`~hardening_agent.checks.base.SysctlCheck`.
"""

from __future__ import annotations

from ..models import CheckMetadata, Finding, Severity
from .base import CheckContext, SysctlCheck, read_sysctl

NET_TAGS = frozenset({"kernel", "network", "sysctl"})
MEM_TAGS = frozenset({"kernel", "memory", "sysctl"})


class IPForwardingCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_ip_forwarding_disabled",
        title="IPv4 forwarding is disabled",
        description="net.ipv4.ip_forward must be 0 on hosts that are not routers.",
        severity=Severity.MEDIUM,
        rationale=(
            "A host that forwards packets can be used to pivot between network "
            "segments, bypassing firewall rules that assume traffic terminates "
            "at this machine. Only routers, NAT gateways and container hosts "
            "need this enabled."
        ),
        tags=NET_TAGS | {"cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.2.1",),
    )
    sysctl_key = "net.ipv4.ip_forward"
    expected = "0"

    def audit(self, ctx: CheckContext) -> Finding:
        """Skip on container hosts, where forwarding is required by design.

        Reporting a Docker host as non-compliant for enabling ip_forward is a
        false positive that trains operators to ignore the tool.
        """
        info = ctx.system.host_info()
        if info.virtualization in ("docker", "container"):
            return Finding.skipped(
                "running inside a container; ip_forward is managed by the host",
                virtualization=info.virtualization,
            )
        if ctx.system.path_exists("/var/run/docker.sock") or ctx.system.path_exists(
            "/sys/class/net/docker0"
        ):
            return Finding.skipped(
                "container runtime detected; IPv4 forwarding is required for bridge networking",
                reason="docker_detected",
            )
        return super().audit(ctx)


class SendRedirectsCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_send_redirects_disabled",
        title="ICMP redirect sending is disabled",
        description="net.ipv4.conf.all.send_redirects must be 0.",
        severity=Severity.MEDIUM,
        rationale=(
            "Sending ICMP redirects lets this host alter other machines' routing "
            "tables. On a non-router it has no legitimate use and leaks topology."
        ),
        tags=NET_TAGS | {"cis"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.2.2",),
    )
    sysctl_key = "net.ipv4.conf.all.send_redirects"
    expected = "0"


class AcceptRedirectsCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_accept_redirects_disabled",
        title="ICMP redirect acceptance is disabled",
        description="net.ipv4.conf.all.accept_redirects must be 0.",
        severity=Severity.HIGH,
        rationale=(
            "Accepting ICMP redirects allows an attacker on the local segment to "
            "rewrite this host's routing table and silently reroute traffic "
            "through a machine they control."
        ),
        tags=NET_TAGS | {"cis", "mitm"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.3.1",),
    )
    sysctl_key = "net.ipv4.conf.all.accept_redirects"
    expected = "0"


class SourceRoutingCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_source_routing_disabled",
        title="Source-routed packet acceptance is disabled",
        description="net.ipv4.conf.all.accept_source_route must be 0.",
        severity=Severity.HIGH,
        rationale=(
            "Source-routed packets let the sender dictate their return path, "
            "which defeats ingress filtering and can be used to reach hosts that "
            "should be unreachable from the attacker's network."
        ),
        tags=NET_TAGS | {"cis", "spoofing"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.3.2",),
    )
    sysctl_key = "net.ipv4.conf.all.accept_source_route"
    expected = "0"


class ReversePathFilterCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_reverse_path_filter_enabled",
        title="Reverse path filtering is enabled",
        description="net.ipv4.conf.all.rp_filter must be 1.",
        severity=Severity.MEDIUM,
        rationale=(
            "Reverse path filtering drops packets whose source address is not "
            "reachable via the interface they arrived on, which blocks the "
            "simplest form of IP address spoofing."
        ),
        tags=NET_TAGS | {"cis", "spoofing"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.3.7",),
    )
    sysctl_key = "net.ipv4.conf.all.rp_filter"
    expected = "1"


class TCPSynCookiesCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_tcp_syncookies_enabled",
        title="TCP SYN cookies are enabled",
        description="net.ipv4.tcp_syncookies must be 1.",
        severity=Severity.MEDIUM,
        rationale=(
            "SYN cookies let the kernel complete handshakes without allocating "
            "connection state, so a SYN flood cannot exhaust the backlog queue "
            "and deny service to legitimate clients."
        ),
        tags=NET_TAGS | {"cis", "availability"},
        remediable=True,
        references=("CIS Ubuntu 24.04 3.3.8",),
    )
    sysctl_key = "net.ipv4.tcp_syncookies"
    expected = "1"


class ASLRCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_aslr_enabled",
        title="Full address space layout randomisation is enabled",
        description="kernel.randomize_va_space must be 2.",
        severity=Severity.HIGH,
        rationale=(
            "ASLR randomises the memory layout of every process, which is the "
            "baseline mitigation that makes memory-corruption exploits "
            "probabilistic rather than reliable. Value 2 randomises the heap too."
        ),
        tags=MEM_TAGS | {"cis", "exploit-mitigation"},
        remediable=True,
        references=("CIS Ubuntu 24.04 1.5.3",),
    )
    sysctl_key = "kernel.randomize_va_space"
    expected = "2"


class KptrRestrictCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_kptr_restrict_enabled",
        title="Kernel pointer addresses are hidden from unprivileged users",
        description="kernel.kptr_restrict must be 1 or 2.",
        severity=Severity.MEDIUM,
        rationale=(
            "Leaked kernel pointers via /proc defeat KASLR and hand an attacker "
            "the exact addresses needed to turn a local bug into a root exploit."
        ),
        tags=MEM_TAGS | {"exploit-mitigation"},
        remediable=True,
        references=("NIST 800-53 SC-30",),
    )
    sysctl_key = "kernel.kptr_restrict"
    expected = "1"

    def audit(self, ctx: CheckContext) -> Finding:
        actual = read_sysctl(ctx.system, self.sysctl_key)
        if actual is None:
            return Finding.skipped(
                "kernel.kptr_restrict is not exposed by this kernel", sysctl=self.sysctl_key
            )
        evidence = {"sysctl": self.sysctl_key, "actual": actual, "expected": "1 or 2"}
        if actual in ("1", "2"):
            return Finding.passed(f"{self.sysctl_key} = {actual}", **evidence)
        return Finding.failed(f"{self.sysctl_key} = {actual}, expected 1 or 2", **evidence)


class DmesgRestrictCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_dmesg_restrict_enabled",
        title="Kernel ring buffer is restricted to privileged users",
        description="kernel.dmesg_restrict must be 1.",
        severity=Severity.LOW,
        rationale=(
            "dmesg output routinely contains kernel addresses, hardware details "
            "and crash traces that assist local privilege escalation."
        ),
        tags=MEM_TAGS | {"information-disclosure"},
        remediable=True,
        references=("NIST 800-53 SC-30",),
    )
    sysctl_key = "kernel.dmesg_restrict"
    expected = "1"


class UnprivilegedBPFCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_unprivileged_bpf_disabled",
        title="Unprivileged eBPF is disabled",
        description="kernel.unprivileged_bpf_disabled must be 1 or 2.",
        severity=Severity.HIGH,
        rationale=(
            "The eBPF verifier is a large, complex attack surface reachable from "
            "unprivileged user space and has produced multiple local privilege "
            "escalation CVEs. Disabling unprivileged access removes that path."
        ),
        tags=MEM_TAGS | {"exploit-mitigation", "bpf"},
        remediable=True,
        references=("CIS Ubuntu 24.04 1.5.5",),
    )
    sysctl_key = "kernel.unprivileged_bpf_disabled"
    expected = "2"

    def audit(self, ctx: CheckContext) -> Finding:
        actual = read_sysctl(ctx.system, self.sysctl_key)
        if actual is None:
            return Finding.skipped(
                "kernel.unprivileged_bpf_disabled is not exposed by this kernel",
                sysctl=self.sysctl_key,
            )
        evidence = {"sysctl": self.sysctl_key, "actual": actual, "expected": "1 or 2"}
        if actual in ("1", "2"):
            return Finding.passed(f"{self.sysctl_key} = {actual}", **evidence)
        return Finding.failed(
            f"{self.sysctl_key} = {actual}, expected 1 (disabled) or 2 (locked)", **evidence
        )


class CoreDumpRestrictCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_setuid_core_dumps_disabled",
        title="Core dumps from setuid programs are disabled",
        description="fs.suid_dumpable must be 0.",
        severity=Severity.MEDIUM,
        rationale=(
            "A core dump from a setuid binary can contain privileged memory "
            "including credentials and keys, written to a location the "
            "unprivileged invoking user may be able to read."
        ),
        tags=MEM_TAGS | {"cis", "information-disclosure"},
        remediable=True,
        references=("CIS Ubuntu 24.04 1.5.1",),
    )
    sysctl_key = "fs.suid_dumpable"
    expected = "0"


class ProtectHardlinksCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_protected_hardlinks_enabled",
        title="Hardlink protection is enabled",
        description="fs.protected_hardlinks must be 1.",
        severity=Severity.MEDIUM,
        rationale=(
            "Without this, a user can hardlink to a file they cannot read and "
            "trick a privileged process into operating on it -- a classic "
            "time-of-check/time-of-use privilege escalation pattern."
        ),
        tags=frozenset({"kernel", "filesystem", "sysctl", "cis"}),
        remediable=True,
        references=("CIS Ubuntu 24.04 1.5.6",),
    )
    sysctl_key = "fs.protected_hardlinks"
    expected = "1"


class ProtectSymlinksCheck(SysctlCheck):
    metadata = CheckMetadata(
        check_id="kernel_protected_symlinks_enabled",
        title="Symlink protection is enabled",
        description="fs.protected_symlinks must be 1.",
        severity=Severity.MEDIUM,
        rationale=(
            "Restricts symlink following in world-writable sticky directories "
            "such as /tmp, blocking the symlink-race attacks that let a local "
            "user redirect a root process's writes."
        ),
        tags=frozenset({"kernel", "filesystem", "sysctl", "cis"}),
        remediable=True,
        references=("CIS Ubuntu 24.04 1.5.7",),
    )
    sysctl_key = "fs.protected_symlinks"
    expected = "1"


CHECKS = (
    IPForwardingCheck,
    SendRedirectsCheck,
    AcceptRedirectsCheck,
    SourceRoutingCheck,
    ReversePathFilterCheck,
    TCPSynCookiesCheck,
    ASLRCheck,
    KptrRestrictCheck,
    DmesgRestrictCheck,
    UnprivilegedBPFCheck,
    CoreDumpRestrictCheck,
    ProtectHardlinksCheck,
    ProtectSymlinksCheck,
)
