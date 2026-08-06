#!/usr/bin/env bash
#
# Verify a host can run the hardening agent before installing it.
#
# Read-only. Exits 0 if the host is ready, 1 if a hard requirement is missing.
# Run this first on an unfamiliar host, or from configuration management as a
# gate before the install step.
#
# Usage: ./scripts/preflight.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

FAILURES=0
WARNINGS=0

pass() { log_ok "$*"; }
fail() { log_error "$*"; FAILURES=$((FAILURES + 1)); }
warn() { log_warn "$*"; WARNINGS=$((WARNINGS + 1)); }

check_os() {
  if [[ ! -r /etc/os-release ]]; then
    fail "/etc/os-release is missing; cannot identify the distribution"
    return
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) pass "distribution: ${PRETTY_NAME:-${ID}}" ;;
    *)             warn "distribution '${ID:-unknown}' is untested; apt-based checks will SKIP" ;;
  esac
}

check_python() {
  local python_bin
  if python_bin="$(find_python)"; then
    pass "python: ${python_bin} ($("${python_bin}" --version 2>&1))"
  else
    fail "python 3.13+ not found. Install with: apt-get install -y python3.13 python3.13-venv"
    return
  fi
  # venv is a separate package on Debian/Ubuntu and its absence only surfaces
  # at install time, which is a frustrating place to discover it.
  if "${python_bin}" -c 'import venv' 2>/dev/null; then
    pass "python venv module available"
  else
    fail "python venv module missing. Install with: apt-get install -y python3.13-venv"
  fi
}

check_init() {
  if [[ -d /run/systemd/system ]]; then
    pass "systemd is the active init system"
  else
    fail "systemd not detected; the timer and exporter units cannot be installed"
  fi
}

check_privileges() {
  if [[ ${EUID} -eq 0 ]]; then
    pass "running as root"
  else
    warn "not running as root; installation will require sudo"
  fi
}

check_proc() {
  local path
  for path in /proc/sys /proc/mounts /proc/meminfo; do
    if [[ -r "${path}" ]]; then
      pass "readable: ${path}"
    else
      fail "unreadable: ${path} (kernel and host metric checks will not work)"
    fi
  done
}

check_disk_space() {
  # The venv plus pip build artefacts need well under 100 MB; 200 is comfortable.
  local available_mb
  available_mb="$(df -Pm /opt 2>/dev/null | awk 'NR==2 {print $4}')" || available_mb=""
  if [[ -z "${available_mb}" ]]; then
    warn "could not determine free space on /opt"
  elif (( available_mb < 200 )); then
    fail "only ${available_mb} MB free on /opt; at least 200 MB recommended"
  else
    pass "disk space on /opt: ${available_mb} MB free"
  fi
}

check_port() {
  local port="${1:-9101}"
  if command -v ss >/dev/null 2>&1; then
    if ss -lntH "sport = :${port}" 2>/dev/null | grep -q .; then
      warn "port ${port} is already in use; set exporter.port in agent.toml"
    else
      pass "port ${port} is free for the metrics exporter"
    fi
  else
    warn "ss not available; cannot verify port ${port} is free"
  fi
}

check_conflicting_install() {
  if [[ -d "${INSTALL_DIR}" ]]; then
    warn "${INSTALL_DIR} already exists; install.sh will upgrade in place"
  else
    pass "no previous installation at ${INSTALL_DIR}"
  fi
}

check_optional_tools() {
  local tool
  for tool in ufw nft auditd systemctl apt-get; do
    if command -v "${tool}" >/dev/null 2>&1; then
      pass "optional tool present: ${tool}"
    else
      warn "optional tool absent: ${tool} (related checks will report SKIP)"
    fi
  done
}

main() {
  log_info "hardening-agent preflight"
  echo >&2

  check_os
  check_python
  check_init
  check_privileges
  check_proc
  check_disk_space
  check_port 9101
  check_conflicting_install
  check_optional_tools

  echo >&2
  if (( FAILURES > 0 )); then
    log_error "preflight FAILED: ${FAILURES} blocking issue(s), ${WARNINGS} warning(s)"
    exit 1
  fi
  log_ok "preflight PASSED with ${WARNINGS} warning(s); this host is ready"
}

main "$@"
