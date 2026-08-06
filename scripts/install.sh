#!/usr/bin/env bash
#
# Install the Linux hardening agent as a systemd service.
#
# Creates a dedicated system user, installs a self-contained virtualenv under
# /opt, writes the default config if absent, and enables:
#   * hardening-agent.timer     -- periodic audit that publishes the textfile
#   * hardening-agent-exporter  -- HTTP metrics endpoint on 127.0.0.1:9101
#
# The installer is idempotent: running it twice is safe and upgrades in place.
# It never modifies the host's security configuration -- that is what
# `hardening-agent remediate` is for, and it is a separate, explicit act.
#
# Usage:
#   sudo ./scripts/install.sh [--no-exporter] [--no-timer] [--yes]
#
# Environment:
#   FORCE_INSTALL=1   install on an unsupported distribution
#   ASSUME_YES=1      never prompt

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

INSTALL_EXPORTER=1
INSTALL_TIMER=1

usage() {
  usage_from_header "$0"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-exporter) INSTALL_EXPORTER=0 ;;
    --no-timer)    INSTALL_TIMER=0 ;;
    --yes|-y)      ASSUME_YES=1 ;;
    --help|-h)     usage ;;
    *)             die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
export ASSUME_YES="${ASSUME_YES:-0}"

main() {
  require_root
  check_supported_os
  require_systemd

  log_info "installing ${AGENT_NAME} from ${REPO_ROOT}"

  local python_bin
  if ! python_bin="$(find_python)"; then
    die "python 3.13 or newer is required but was not found.
     On Ubuntu 24.04:  apt-get install -y python3.13 python3.13-venv"
  fi
  log_info "using interpreter ${python_bin} ($("${python_bin}" --version))"

  # -- directories ----------------------------------------------------------
  ensure_group
  ensure_user

  ensure_dir "${INSTALL_DIR}" 0755 "root:root"
  ensure_dir "${CONFIG_DIR}"  0755 "root:root"
  # The agent writes metrics here as an unprivileged user.
  ensure_dir "${STATE_DIR}"   0750 "${AGENT_USER}:${AGENT_GROUP}"
  ensure_dir "${TEXTFILE_DIR}" 0755 "${AGENT_USER}:${AGENT_GROUP}"
  ensure_dir "${LOG_DIR}"     0750 "${AGENT_USER}:${AGENT_GROUP}"
  # Backups hold copies of /etc/shadow-adjacent files: root-only, always.
  ensure_dir "${BACKUP_DIR}"  0700 "root:root"
  log_ok "created directory layout"

  # -- application ----------------------------------------------------------
  log_info "building virtualenv at ${INSTALL_DIR}/venv"
  if [[ -d "${INSTALL_DIR}/venv" ]]; then
    log_info "existing virtualenv found; upgrading in place"
  else
    "${python_bin}" -m venv "${INSTALL_DIR}/venv" ||
      die "failed to create virtualenv. Is python3.13-venv installed?"
  fi

  "${INSTALL_DIR}/venv/bin/python" -m pip install --quiet --upgrade pip >/dev/null
  # The agent has no runtime dependencies, so this reaches the network only for
  # pip/build tooling. --no-input keeps it non-interactive under systemd.
  "${INSTALL_DIR}/venv/bin/python" -m pip install --quiet --no-input "${REPO_ROOT}" ||
    die "failed to install the agent package"
  log_ok "installed the agent package"

  ln -sfn "${INSTALL_DIR}/venv/bin/hardening-agent" "${BIN_LINK}"
  log_ok "linked ${BIN_LINK}"

  # Helper scripts, so an operator can point ExecStart at collect_metrics.sh
  # without needing the source tree on the host.
  ensure_dir "${INSTALL_DIR}/bin" 0755 "root:root"
  install -m 0755 -o root -g root \
    "${REPO_ROOT}/scripts/collect_metrics.sh" "${INSTALL_DIR}/bin/"
  install -m 0755 -o root -g root \
    "${REPO_ROOT}/scripts/preflight.sh" "${INSTALL_DIR}/bin/"
  ensure_dir "${INSTALL_DIR}/bin/lib" 0755 "root:root"
  install -m 0644 -o root -g root \
    "${REPO_ROOT}/scripts/lib/common.sh" "${INSTALL_DIR}/bin/lib/"
  log_ok "installed helper scripts to ${INSTALL_DIR}/bin"

  # -- configuration --------------------------------------------------------
  # Never clobber an operator's tuned configuration on upgrade.
  if [[ -f "${CONFIG_DIR}/agent.toml" ]]; then
    log_info "keeping existing ${CONFIG_DIR}/agent.toml"
    install -m 0644 -o root -g root \
      "${REPO_ROOT}/config/agent.toml" "${CONFIG_DIR}/agent.toml.dist"
    log_info "reference config written to ${CONFIG_DIR}/agent.toml.dist"
  else
    install -m 0644 -o root -g root \
      "${REPO_ROOT}/config/agent.toml" "${CONFIG_DIR}/agent.toml"
    log_ok "installed default config to ${CONFIG_DIR}/agent.toml"
  fi

  # -- systemd units --------------------------------------------------------
  install -m 0644 -o root -g root \
    "${REPO_ROOT}/packaging/systemd/hardening-agent.service" "${SYSTEMD_DIR}/"
  install -m 0644 -o root -g root \
    "${REPO_ROOT}/packaging/systemd/hardening-agent.timer" "${SYSTEMD_DIR}/"
  install -m 0644 -o root -g root \
    "${REPO_ROOT}/packaging/systemd/hardening-agent-exporter.service" "${SYSTEMD_DIR}/"
  log_ok "installed systemd units"

  systemd_reload

  if [[ "${INSTALL_TIMER}" == "1" ]]; then
    systemctl enable --now hardening-agent.timer
    log_ok "enabled hardening-agent.timer"
  else
    log_info "skipping timer (--no-timer)"
  fi

  if [[ "${INSTALL_EXPORTER}" == "1" ]]; then
    systemctl enable --now hardening-agent-exporter.service
    log_ok "enabled hardening-agent-exporter.service"
  else
    log_info "skipping exporter (--no-exporter)"
  fi

  # -- verification ---------------------------------------------------------
  log_info "running a verification audit"
  if "${BIN_LINK}" --version >/dev/null; then
    log_ok "agent responds: $("${BIN_LINK}" --version)"
  else
    die "the installed agent did not run"
  fi

  # An audit that finds problems exits non-zero; that is a successful install,
  # not a failure, so the exit code is captured rather than allowed to abort.
  local audit_rc=0
  "${BIN_LINK}" audit --log-level ERROR >/dev/null 2>&1 || audit_rc=$?
  case "${audit_rc}" in
    0) log_ok "verification audit passed with no findings" ;;
    1) log_warn "verification audit completed with findings (expected on a fresh host)" ;;
    *) log_warn "verification audit exited with code ${audit_rc}; check the logs" ;;
  esac

  print_summary
}

print_summary() {
  cat >&2 <<EOF

${C_GREEN}${AGENT_NAME} installed successfully.${C_RESET}

  Run an audit          hardening-agent audit
  Preview fixes         hardening-agent remediate --dry-run
  Apply safe fixes      sudo hardening-agent remediate --yes
  Metrics endpoint      curl -s localhost:9101/metrics
  Health check          curl -s localhost:9101/healthz

  Config                ${CONFIG_DIR}/agent.toml
  Metrics textfile      ${TEXTFILE_DIR}/hardening_agent.prom
  Backups               ${BACKUP_DIR}
  Logs                  journalctl -u hardening-agent-exporter -f

  Timer status          systemctl status hardening-agent.timer
  Next scheduled run    systemctl list-timers hardening-agent.timer

To have node_exporter publish the compliance metrics, start it with:
  --collector.textfile.directory=${TEXTFILE_DIR}

EOF
}

main "$@"
