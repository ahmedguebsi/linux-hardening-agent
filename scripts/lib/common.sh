#!/usr/bin/env bash
# Shared helpers for the hardening-agent shell scripts.
#
# Sourced, never executed directly. Every function here is safe to call from a
# script running under `set -euo pipefail`.

# Guard against double-sourcing.
if [[ -n "${_HARDENING_AGENT_COMMON_SH:-}" ]]; then
  return 0
fi
readonly _HARDENING_AGENT_COMMON_SH=1

# --- installation layout ----------------------------------------------------
readonly AGENT_NAME="hardening-agent"
readonly AGENT_USER="hardening-agent"
readonly AGENT_GROUP="hardening-agent"
readonly INSTALL_DIR="/opt/hardening-agent"
readonly CONFIG_DIR="/etc/hardening-agent"
readonly STATE_DIR="/var/lib/hardening-agent"
readonly TEXTFILE_DIR="${STATE_DIR}/textfile"
readonly BACKUP_DIR="/var/backups/hardening-agent"
readonly LOG_DIR="/var/log/hardening-agent"
readonly BIN_LINK="/usr/local/bin/hardening-agent"
readonly SYSTEMD_DIR="/etc/systemd/system"

# --- output -----------------------------------------------------------------
# Colour only when stderr is a terminal and NO_COLOR is unset, so piped output
# and journald entries stay clean.
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  readonly C_RESET=$'\033[0m'
  readonly C_RED=$'\033[31m'
  readonly C_GREEN=$'\033[32m'
  readonly C_YELLOW=$'\033[33m'
  readonly C_BLUE=$'\033[34m'
else
  readonly C_RESET="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
fi

log_info()  { printf '%s[ info]%s %s\n' "${C_BLUE}"   "${C_RESET}" "$*" >&2; }
log_ok()    { printf '%s[  ok ]%s %s\n' "${C_GREEN}"  "${C_RESET}" "$*" >&2; }
log_warn()  { printf '%s[ warn]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
log_error() { printf '%s[error]%s %s\n' "${C_RED}"    "${C_RESET}" "$*" >&2; }

die() {
  log_error "$*"
  exit 1
}

# --- preconditions ----------------------------------------------------------
require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    die "this script must run as root (try: sudo $0)"
  fi
}

require_command() {
  local cmd="$1"
  command -v "${cmd}" >/dev/null 2>&1 || die "required command not found: ${cmd}"
}

require_systemd() {
  [[ -d /run/systemd/system ]] || die "systemd is not the active init system"
  require_command systemctl
}

# Refuse to run on a distribution the checks were not written for, unless the
# operator explicitly overrides. Silently doing the wrong thing on a foreign
# distro is worse than stopping.
check_supported_os() {
  local id="" version_id=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    version_id="${VERSION_ID:-}"
  fi

  case "${id}" in
    ubuntu|debian)
      log_info "detected ${id} ${version_id}"
      ;;
    *)
      if [[ "${FORCE_INSTALL:-0}" == "1" ]]; then
        log_warn "unsupported distribution '${id:-unknown}'; continuing (FORCE_INSTALL=1)"
      else
        die "unsupported distribution '${id:-unknown}'. Debian/Ubuntu expected. Set FORCE_INSTALL=1 to override."
      fi
      ;;
  esac
}

# Find a Python new enough for the agent (3.13+ per pyproject).
find_python() {
  local candidate
  for candidate in python3.13 python3; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      if "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)' 2>/dev/null; then
        printf '%s' "$(command -v "${candidate}")"
        return 0
      fi
    fi
  done
  return 1
}

# --- system objects ---------------------------------------------------------
ensure_group() {
  if getent group "${AGENT_GROUP}" >/dev/null 2>&1; then
    log_info "group ${AGENT_GROUP} already exists"
  else
    groupadd --system "${AGENT_GROUP}"
    log_ok "created group ${AGENT_GROUP}"
  fi
}

# A dedicated system account with no shell and no home: if the agent process is
# ever compromised, the account it runs as should be worth nothing.
ensure_user() {
  if getent passwd "${AGENT_USER}" >/dev/null 2>&1; then
    log_info "user ${AGENT_USER} already exists"
  else
    useradd --system \
            --gid "${AGENT_GROUP}" \
            --home-dir "${STATE_DIR}" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Linux hardening agent" \
            "${AGENT_USER}"
    log_ok "created system user ${AGENT_USER}"
  fi
}

ensure_dir() {
  local path="$1" mode="$2" owner="${3:-root:root}"
  mkdir -p "${path}"
  chown "${owner}" "${path}"
  chmod "${mode}" "${path}"
}

# --- systemd ----------------------------------------------------------------
systemd_reload() {
  systemctl daemon-reload
  log_ok "reloaded systemd units"
}

unit_exists() {
  systemctl list-unit-files "$1" >/dev/null 2>&1 &&
    [[ -f "${SYSTEMD_DIR}/$1" ]]
}

stop_and_disable() {
  local unit="$1"
  if systemctl is-active --quiet "${unit}" 2>/dev/null; then
    systemctl stop "${unit}" || log_warn "could not stop ${unit}"
    log_ok "stopped ${unit}"
  fi
  if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
    systemctl disable "${unit}" >/dev/null 2>&1 || log_warn "could not disable ${unit}"
    log_ok "disabled ${unit}"
  fi
}

# Print a script's leading comment block as its help text.
#
# Hardcoded `sed -n '2,20p'` ranges silently drift the moment anyone edits the
# header, leaking code into --help output. This walks the file instead: skip the
# shebang, print comment lines with the leading "# " stripped, stop at the first
# line that is not a comment.
usage_from_header() {
  awk '
    NR == 1 { next }                       # shebang
    /^#/    { sub(/^# ?/, ""); print; next }
            { exit }                       # first non-comment line ends the block
  ' "$1"
}

confirm() {
  local prompt="$1"
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi
  # Reading from /dev/tty rather than stdin keeps this working when the script
  # is piped (curl | bash), where stdin is the script itself.
  local reply=""
  if [[ -r /dev/tty ]]; then
    read -r -p "${prompt} [y/N] " reply </dev/tty || reply=""
  else
    log_warn "no terminal available for confirmation; assuming no"
    return 1
  fi
  [[ "${reply}" =~ ^[Yy]$ ]]
}
