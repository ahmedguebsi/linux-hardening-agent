#!/usr/bin/env bash
#
# Remove the Linux hardening agent.
#
# By default this removes the software but KEEPS your data: audit backups under
# /var/backups/hardening-agent and the configuration in /etc/hardening-agent.
# That is deliberate -- the backups are the only record of what the agent
# changed on this host, and deleting them by default would destroy the ability
# to undo a remediation.
#
# Usage:
#   sudo ./scripts/uninstall.sh            # remove software, keep data
#   sudo ./scripts/uninstall.sh --purge    # remove everything including backups
#   sudo ./scripts/uninstall.sh --yes      # no prompts
#
# This script never reverts hardening changes the agent applied to the host.
# To undo those, restore from /var/backups/hardening-agent before purging.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

PURGE=0
REMOVE_USER=1

usage() {
  usage_from_header "$0"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)     PURGE=1 ;;
    --keep-user) REMOVE_USER=0 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --help|-h)   usage ;;
    *)           die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
export ASSUME_YES="${ASSUME_YES:-0}"

main() {
  require_root

  if [[ "${PURGE}" == "1" ]]; then
    log_warn "--purge will delete configuration AND all remediation backups in ${BACKUP_DIR}"
    log_warn "after this you will NOT be able to roll back changes the agent made"
    confirm "Permanently delete all hardening-agent data?" ||
      die "aborted by user"
  fi

  # -- services -------------------------------------------------------------
  if [[ -d /run/systemd/system ]]; then
    stop_and_disable hardening-agent.timer
    stop_and_disable hardening-agent.service
    stop_and_disable hardening-agent-exporter.service

    local unit
    for unit in hardening-agent.timer hardening-agent.service \
                hardening-agent-exporter.service; do
      if [[ -f "${SYSTEMD_DIR}/${unit}" ]]; then
        rm -f "${SYSTEMD_DIR}/${unit}"
        log_ok "removed ${SYSTEMD_DIR}/${unit}"
      fi
    done

    systemctl daemon-reload
    # Clears the "unit files changed on disk" state for the removed units.
    systemctl reset-failed hardening-agent.service \
                           hardening-agent-exporter.service 2>/dev/null || true
    log_ok "reloaded systemd"
  else
    log_warn "systemd not running; skipping service removal"
  fi

  # -- binaries -------------------------------------------------------------
  if [[ -L "${BIN_LINK}" || -f "${BIN_LINK}" ]]; then
    rm -f "${BIN_LINK}"
    log_ok "removed ${BIN_LINK}"
  fi

  # Guard against a catastrophic expansion: only ever remove the exact,
  # hardcoded install path, and only if it looks like ours.
  if [[ -d "${INSTALL_DIR}" ]]; then
    if [[ "${INSTALL_DIR}" == "/opt/hardening-agent" && -d "${INSTALL_DIR}/venv" ]]; then
      rm -rf -- "${INSTALL_DIR}"
      log_ok "removed ${INSTALL_DIR}"
    else
      log_warn "${INSTALL_DIR} does not look like an agent install; leaving it alone"
    fi
  fi

  # -- data -----------------------------------------------------------------
  if [[ "${PURGE}" == "1" ]]; then
    local path
    for path in "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${BACKUP_DIR}"; do
      if [[ -d "${path}" ]]; then
        rm -rf -- "${path}"
        log_ok "removed ${path}"
      fi
    done

    if [[ "${REMOVE_USER}" == "1" ]] && getent passwd "${AGENT_USER}" >/dev/null 2>&1; then
      userdel "${AGENT_USER}" 2>/dev/null || log_warn "could not remove user ${AGENT_USER}"
      log_ok "removed user ${AGENT_USER}"
    fi
    if [[ "${REMOVE_USER}" == "1" ]] && getent group "${AGENT_GROUP}" >/dev/null 2>&1; then
      groupdel "${AGENT_GROUP}" 2>/dev/null || true
      log_ok "removed group ${AGENT_GROUP}"
    fi
  else
    log_info "keeping ${CONFIG_DIR}, ${STATE_DIR} and ${BACKUP_DIR} (use --purge to remove)"
  fi

  cat >&2 <<EOF

${C_GREEN}${AGENT_NAME} removed.${C_RESET}

EOF
  if [[ "${PURGE}" != "1" ]]; then
    cat >&2 <<EOF
Retained on this host:
  ${CONFIG_DIR}    configuration
  ${STATE_DIR}     metrics textfile
  ${BACKUP_DIR}    remediation backups (needed to undo agent changes)

Remove them with: sudo $0 --purge

EOF
  fi
  cat >&2 <<EOF
Note: security settings the agent applied to this host remain in effect.
Uninstalling the agent does not revert them.

EOF
}

main "$@"
