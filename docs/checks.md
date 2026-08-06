# Check catalogue

> **Generated file.** Produced by `scripts/generate_check_docs.py` from the live registry. Do not edit by hand; edit the check's `CheckMetadata` and regenerate.

`hardening-agent` 1.0.0 ships **40 controls**.

| | Count |
| --- | ---: |
| Total controls | 40 |
| Critical severity | 7 |
| High severity | 14 |
| Medium severity | 16 |
| Low severity | 3 |
| Remediable | 35 |
| ...of which flagged risky | 3 |
| Audit-only by design | 5 |

## Reading this document

**Severity** is the impact of the control *failing*, not the difficulty of fixing it. `fail_on_severity` in the config gates the exit code on it.

**Remediable** means the agent can fix it. **Risky** means the fix can sever your access to the host and requires `--allow-risky` on top of `--yes`.

**Rationale** states the actual attack the control prevents. A control nobody can justify is a control nobody will keep enabled.

## SSH (OpenSSH server)

8 control(s).

### `ssh_empty_passwords_disabled`

**SSH rejects accounts with empty passwords**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | remediable |
| Tags | `authentication`, `cis`, `network`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.16 |

PermitEmptyPasswords must be 'no'.

*Why it matters:* An account with an empty password combined with PermitEmptyPasswords yes grants unauthenticated remote shell access to anyone who knows the username.

### `ssh_host_key_permissions`

**SSH private host keys are protected**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | remediable |
| Tags | `cis`, `cryptography`, `network`, `permissions`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.2 |

Private host keys must be mode 0640 or stricter and owned by root.

*Why it matters:* A leaked private host key allows an attacker to impersonate this server and transparently machine-in-the-middle every SSH session, including the credentials and commands within it.

### `ssh_root_login_disabled`

**SSH direct root login is disabled**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | remediable |
| Tags | `access-control`, `cis`, `network`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.7, NIST 800-53 AC-6 |

PermitRootLogin must be 'no' or 'prohibit-password'.

*Why it matters:* Direct root login removes per-user accountability and gives brute-force attackers a known-valid username. Administrators should log in as themselves and escalate with sudo, which leaves an audit trail.

### `ssh_config_permissions`

**sshd_config is owned by root and not world-readable**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `network`, `permissions`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.1 |

/etc/ssh/sshd_config must be mode 0600 or stricter, owned by root.

*Why it matters:* A writable sshd_config lets a local user grant themselves remote root access on the next daemon restart. A world-readable one leaks the host's authentication posture to any local account.

### `ssh_password_auth_disabled`

**SSH password authentication is disabled**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable (risky) |
| Tags | `authentication`, `cis`, `network`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.15 |

PasswordAuthentication must be 'no'; use public keys.

*Why it matters:* Password authentication is the single largest source of successful SSH compromise via credential stuffing and brute force. Key-based auth is not guessable and does not transmit a reusable secret.

### `ssh_max_auth_tries`

**SSH limits authentication attempts per connection**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `brute-force`, `cis`, `network`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.9 |

MaxAuthTries must be 4 or fewer.

*Why it matters:* Each connection allowing many attempts multiplies brute-force throughput. A low limit forces attackers to pay TCP handshake cost per guess and makes the attempts far more visible in logs.

### `ssh_x11_forwarding_disabled`

**SSH X11 forwarding is disabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `network`, `remote-access`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.10 |

X11Forwarding must be 'no' on servers.

*Why it matters:* X11 forwarding exposes the client's X server to the remote host; a compromised server can capture keystrokes from the client session. Servers have no legitimate need for it.

### `ssh_client_alive_interval`

**SSH idle sessions time out**

| | |
| --- | --- |
| Severity | `low` |
| Remediation | remediable |
| Tags | `cis`, `network`, `remote-access`, `session`, `ssh` |
| References | CIS Ubuntu 24.04 5.1.12 |

ClientAliveInterval must be set to 300 seconds or less (non-zero).

*Why it matters:* Idle sessions left open on an unlocked workstation are a lateral movement opportunity and hold privileged shells open indefinitely.

## Kernel and network stack (sysctl)

13 control(s).

### `kernel_accept_redirects_disabled`

**ICMP redirect acceptance is disabled**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `kernel`, `mitm`, `network`, `sysctl` |
| References | CIS Ubuntu 24.04 3.3.1 |

net.ipv4.conf.all.accept_redirects must be 0.

*Why it matters:* Accepting ICMP redirects allows an attacker on the local segment to rewrite this host's routing table and silently reroute traffic through a machine they control.

### `kernel_aslr_enabled`

**Full address space layout randomisation is enabled**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `exploit-mitigation`, `kernel`, `memory`, `sysctl` |
| References | CIS Ubuntu 24.04 1.5.3 |

kernel.randomize_va_space must be 2.

*Why it matters:* ASLR randomises the memory layout of every process, which is the baseline mitigation that makes memory-corruption exploits probabilistic rather than reliable. Value 2 randomises the heap too.

### `kernel_source_routing_disabled`

**Source-routed packet acceptance is disabled**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `kernel`, `network`, `spoofing`, `sysctl` |
| References | CIS Ubuntu 24.04 3.3.2 |

net.ipv4.conf.all.accept_source_route must be 0.

*Why it matters:* Source-routed packets let the sender dictate their return path, which defeats ingress filtering and can be used to reach hosts that should be unreachable from the attacker's network.

### `kernel_unprivileged_bpf_disabled`

**Unprivileged eBPF is disabled**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `bpf`, `exploit-mitigation`, `kernel`, `memory`, `sysctl` |
| References | CIS Ubuntu 24.04 1.5.5 |

kernel.unprivileged_bpf_disabled must be 1 or 2.

*Why it matters:* The eBPF verifier is a large, complex attack surface reachable from unprivileged user space and has produced multiple local privilege escalation CVEs. Disabling unprivileged access removes that path.

### `kernel_ip_forwarding_disabled`

**IPv4 forwarding is disabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `kernel`, `network`, `sysctl` |
| References | CIS Ubuntu 24.04 3.2.1 |

net.ipv4.ip_forward must be 0 on hosts that are not routers.

*Why it matters:* A host that forwards packets can be used to pivot between network segments, bypassing firewall rules that assume traffic terminates at this machine. Only routers, NAT gateways and container hosts need this enabled.

### `kernel_kptr_restrict_enabled`

**Kernel pointer addresses are hidden from unprivileged users**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `exploit-mitigation`, `kernel`, `memory`, `sysctl` |
| References | NIST 800-53 SC-30 |

kernel.kptr_restrict must be 1 or 2.

*Why it matters:* Leaked kernel pointers via /proc defeat KASLR and hand an attacker the exact addresses needed to turn a local bug into a root exploit.

### `kernel_protected_hardlinks_enabled`

**Hardlink protection is enabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `filesystem`, `kernel`, `sysctl` |
| References | CIS Ubuntu 24.04 1.5.6 |

fs.protected_hardlinks must be 1.

*Why it matters:* Without this, a user can hardlink to a file they cannot read and trick a privileged process into operating on it -- a classic time-of-check/time-of-use privilege escalation pattern.

### `kernel_protected_symlinks_enabled`

**Symlink protection is enabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `filesystem`, `kernel`, `sysctl` |
| References | CIS Ubuntu 24.04 1.5.7 |

fs.protected_symlinks must be 1.

*Why it matters:* Restricts symlink following in world-writable sticky directories such as /tmp, blocking the symlink-race attacks that let a local user redirect a root process's writes.

### `kernel_reverse_path_filter_enabled`

**Reverse path filtering is enabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `kernel`, `network`, `spoofing`, `sysctl` |
| References | CIS Ubuntu 24.04 3.3.7 |

net.ipv4.conf.all.rp_filter must be 1.

*Why it matters:* Reverse path filtering drops packets whose source address is not reachable via the interface they arrived on, which blocks the simplest form of IP address spoofing.

### `kernel_send_redirects_disabled`

**ICMP redirect sending is disabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `kernel`, `network`, `sysctl` |
| References | CIS Ubuntu 24.04 3.2.2 |

net.ipv4.conf.all.send_redirects must be 0.

*Why it matters:* Sending ICMP redirects lets this host alter other machines' routing tables. On a non-router it has no legitimate use and leaks topology.

### `kernel_setuid_core_dumps_disabled`

**Core dumps from setuid programs are disabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `information-disclosure`, `kernel`, `memory`, `sysctl` |
| References | CIS Ubuntu 24.04 1.5.1 |

fs.suid_dumpable must be 0.

*Why it matters:* A core dump from a setuid binary can contain privileged memory including credentials and keys, written to a location the unprivileged invoking user may be able to read.

### `kernel_tcp_syncookies_enabled`

**TCP SYN cookies are enabled**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `availability`, `cis`, `kernel`, `network`, `sysctl` |
| References | CIS Ubuntu 24.04 3.3.8 |

net.ipv4.tcp_syncookies must be 1.

*Why it matters:* SYN cookies let the kernel complete handshakes without allocating connection state, so a SYN flood cannot exhaust the backlog queue and deny service to legitimate clients.

### `kernel_dmesg_restrict_enabled`

**Kernel ring buffer is restricted to privileged users**

| | |
| --- | --- |
| Severity | `low` |
| Remediation | remediable |
| Tags | `information-disclosure`, `kernel`, `memory`, `sysctl` |
| References | NIST 800-53 SC-30 |

kernel.dmesg_restrict must be 1.

*Why it matters:* dmesg output routinely contains kernel addresses, hardware details and crash traces that assist local privilege escalation.

## Filesystem permissions and layout

9 control(s).

### `fs_shadow_permissions`

**/etc/shadow is not readable by non-root users**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | remediable |
| Tags | `accounts`, `cis`, `credentials`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 6.1.2 |

/etc/shadow must be mode 0640 or stricter, owned by root.

*Why it matters:* /etc/shadow holds password hashes. Any local read gives an attacker an offline cracking target with no rate limit and no logging.

### `fs_sudoers_permissions`

**/etc/sudoers is restricted**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | remediable |
| Tags | `cis`, `filesystem`, `permissions`, `privilege-escalation` |
| References | CIS Ubuntu 24.04 5.3.1 |

/etc/sudoers must be mode 0440 or stricter, owned by root:root.

*Why it matters:* Write access to /etc/sudoers is a direct, silent path to root for any local account.

### `fs_crontab_permissions`

**/etc/crontab is restricted to root**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `cron`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 2.4.1.1 |

/etc/crontab must be mode 0600 or stricter, owned by root:root.

*Why it matters:* Cron entries execute as root on a schedule. Write access to the crontab is equivalent to root, and read access reveals scheduled jobs that an attacker can target or predict.

### `fs_gshadow_permissions`

**/etc/gshadow is not readable by non-root users**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `accounts`, `cis`, `credentials`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 6.1.4 |

/etc/gshadow must be mode 0640 or stricter, owned by root.

*Why it matters:* /etc/gshadow contains group password hashes; exposure allows an attacker to join privileged groups such as sudo or docker.

### `fs_no_world_writable_in_etc`

**No world-writable files in /etc**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | audit-only |
| Tags | `cis`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 6.1.9 |

Files under /etc must not be writable by all users.

*Why it matters:* A world-writable file in /etc is a configuration takeover: an unprivileged user edits it and waits for a privileged process to read it.

### `fs_passwd_permissions`

**/etc/passwd has correct permissions**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `accounts`, `cis`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 6.1.1 |

/etc/passwd must be mode 0644 or stricter, owned by root:root.

*Why it matters:* /etc/passwd must stay world-readable for name resolution, but a writable /etc/passwd is instant privilege escalation: add a UID 0 entry and log in as it.

### `fs_tmp_sticky_bit`

**World-writable directories have the sticky bit set**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 1.1.2.1 |

/tmp, /var/tmp and /dev/shm must have the sticky bit (mode 1777).

*Why it matters:* Without the sticky bit, any user can delete or replace another user's files in a shared directory. That enables file-substitution attacks against processes that read from /tmp.

### `fs_group_permissions`

**/etc/group has correct permissions**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `accounts`, `cis`, `filesystem`, `permissions` |
| References | CIS Ubuntu 24.04 6.1.3 |

/etc/group must be mode 0644 or stricter, owned by root:root.

*Why it matters:* A writable /etc/group lets a local user add themselves to sudo, docker, or disk and escalate to root.

### `fs_tmp_separate_partition`

**/tmp is a separate mount with nodev,nosuid,noexec**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | audit-only |
| Tags | `cis`, `filesystem`, `mounts`, `permissions` |
| References | CIS Ubuntu 24.04 1.1.2.1 |

/tmp should be its own mount point carrying hardening options.

*Why it matters:* A separate /tmp stops a runaway process filling the root filesystem, and nosuid/noexec prevent an attacker from staging and executing a payload in the one directory every user can write to.

## User accounts and authentication

5 control(s).

### `accounts_no_empty_passwords`

**No account has an empty password**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | remediable (risky) |
| Tags | `accounts`, `authentication`, `cis`, `credentials` |
| References | CIS Ubuntu 24.04 6.2.1 |

Every /etc/shadow entry must have a password hash or be locked.

*Why it matters:* An empty password field means the account authenticates with no credential at all. Combined with any local or remote login path it is unauthenticated access.

### `accounts_single_uid_zero`

**root is the only account with UID 0**

| | |
| --- | --- |
| Severity | `critical` |
| Remediation | audit-only |
| Tags | `accounts`, `authentication`, `cis`, `persistence`, `privilege-escalation` |
| References | CIS Ubuntu 24.04 6.2.9 |

No account other than root may have UID 0.

*Why it matters:* A second UID 0 account is full root access under a name that does not look like root, which is a classic persistence mechanism that survives password rotation and is easy to overlook in an audit.

### `accounts_root_home_permissions`

**root's home directory is not accessible to other users**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `accounts`, `authentication`, `cis`, `permissions` |
| References | CIS Ubuntu 24.04 6.2.7 |

/root must be mode 0700 or stricter.

*Why it matters:* /root commonly holds SSH keys, cloud credentials, shell history and backup archives. Any non-root read is a credential harvest.

### `accounts_system_accounts_nologin`

**System accounts cannot log in interactively**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | audit-only |
| Tags | `accounts`, `authentication`, `cis`, `service-accounts` |
| References | CIS Ubuntu 24.04 6.2.11 |

Non-root accounts below UID_MIN must use a nologin shell.

*Why it matters:* Service accounts such as www-data or postgres should never have an interactive shell. If a service is compromised, a valid shell turns code execution into a comfortable foothold with a working login.

### `accounts_password_max_days`

**Password expiry policy is configured**

| | |
| --- | --- |
| Severity | `low` |
| Remediation | remediable |
| Tags | `accounts`, `authentication`, `cis`, `policy` |
| References | CIS Ubuntu 24.04 6.2.2, NIST 800-63B 5.1.1.2 |

PASS_MAX_DAYS in /etc/login.defs must be 365 or fewer.

*Why it matters:* Bounded credential lifetime limits how long a leaked password stays useful. Kept at LOW severity because modern guidance (NIST 800-63B) favours breach-triggered rotation over forced expiry.

## Host services (firewall, auditing, patching, time)

5 control(s).

### `services_firewall_enabled`

**A host firewall is active with a default-deny inbound policy**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable (risky) |
| Tags | `cis`, `firewall`, `network`, `services`, `systemd` |
| References | CIS Ubuntu 24.04 4.1.1 |

ufw or nftables must be active and default-deny for incoming traffic.

*Why it matters:* Security groups protect the north-south edge, but a host firewall is what limits east-west movement once an attacker is already inside the VPC. Default-deny means a service accidentally bound to 0.0.0.0 is not automatically reachable.

### `services_no_pending_security_updates`

**No pending security updates**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | audit-only |
| Tags | `patching`, `services`, `systemd`, `vulnerability` |
| References | CIS Ubuntu 24.04 1.9 |

The host must have no uninstalled security updates.

*Why it matters:* A pending security update is a known, published vulnerability with a working patch that this host has not applied. It is the most directly actionable signal in the entire report.

### `services_unattended_upgrades_enabled`

**Automatic security updates are enabled**

| | |
| --- | --- |
| Severity | `high` |
| Remediation | remediable |
| Tags | `cis`, `patching`, `services`, `systemd` |
| References | CIS Ubuntu 24.04 1.9 |

unattended-upgrades must be installed and active.

*Why it matters:* The overwhelming majority of real-world compromises exploit a vulnerability with an available patch. Automated security patching closes the window between disclosure and remediation without depending on a human being on call.

### `services_auditd_running`

**The audit daemon is installed and running**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `audit`, `cis`, `logging`, `services`, `systemd` |
| References | CIS Ubuntu 24.04 4.1.1.1 |

auditd must be active so kernel audit events are recorded.

*Why it matters:* auditd is the only mechanism that records syscall-level activity such as privilege escalation and file access. Without it, incident response has no local evidence of what an attacker did.

### `services_time_sync_enabled`

**Time synchronisation is active**

| | |
| --- | --- |
| Severity | `medium` |
| Remediation | remediable |
| Tags | `cis`, `logging`, `services`, `systemd`, `time` |
| References | CIS Ubuntu 24.04 2.3.1 |

systemd-timesyncd, chrony or ntpd must be running.

*Why it matters:* Correlating logs across hosts during an incident requires accurate clocks. Clock drift also breaks TLS certificate validation and time-based authentication such as TOTP and AWS SigV4.

## Running a subset

```bash
# One family
hardening-agent audit --tag ssh

# Only the controls that would fail a pipeline
hardening-agent audit --min-severity high

# One control, with full evidence
hardening-agent audit --check ssh_root_login_disabled --verbose

# Everything except one that does not apply to this host
hardening-agent audit --exclude kernel_ip_forwarding_disabled
```

Available tags:

`access-control` `accounts` `audit` `authentication` `availability` `bpf` `brute-force` `cis` `credentials` `cron` `cryptography` `exploit-mitigation` `filesystem` `firewall` `information-disclosure` `kernel` `logging` `memory` `mitm` `mounts` `network` `patching` `permissions` `persistence` `policy` `privilege-escalation` `remote-access` `service-accounts` `services` `session` `spoofing` `ssh` `sysctl` `systemd` `time` `vulnerability`
