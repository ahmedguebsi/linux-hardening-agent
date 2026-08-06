#!/usr/bin/env bash
#
# Publish the compliance metrics textfile for node_exporter.
#
# An ALTERNATIVE entry point to `hardening-agent export`, which is what
# hardening-agent.service runs by default. Use this wrapper instead when you
# want either of the two things it adds:
#
#   * a collector-health metric that is written even when the audit FAILS --
#     otherwise a broken agent looks identical to a healthy, silent one;
#   * the previous textfile preserved on failure, rather than replaced by
#     nothing.
#
# It is also the right entry point when driving the agent from cron on a host
# without systemd.
#
# Point the systemd unit at this script by overriding ExecStart:
#   systemctl edit hardening-agent.service
#     [Service]
#     ExecStart=
#     ExecStart=/opt/hardening-agent/bin/collect_metrics.sh
#
# Usage: ./scripts/collect_metrics.sh [--textfile-dir DIR] [--agent-bin PATH]

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

AGENT_BIN="${AGENT_BIN:-${BIN_LINK}}"
TARGET_DIR="${TEXTFILE_DIR}"
METRIC_FILE="hardening_agent.prom"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --textfile-dir) TARGET_DIR="${2:?--textfile-dir requires a value}"; shift ;;
    --agent-bin)    AGENT_BIN="${2:?--agent-bin requires a value}"; shift ;;
    --help|-h)      usage_from_header "$0"; exit 0 ;;
    *)              die "unknown argument: $1" ;;
  esac
  shift
done

readonly TARGET_FILE="${TARGET_DIR}/${METRIC_FILE}"

# Write the collector's own health metric. Called on both the success and the
# failure path so the series always exists.
emit_scrape_status() {
  local status="$1" duration="$2" tmp
  tmp="$(mktemp "${TARGET_DIR}/.${METRIC_FILE}.status.XXXXXX")"
  {
    echo "# HELP hardening_agent_collector_success Whether the last textfile collection succeeded."
    echo "# TYPE hardening_agent_collector_success gauge"
    echo "hardening_agent_collector_success ${status}"
    echo "# HELP hardening_agent_collector_duration_seconds Duration of the last collection."
    echo "# TYPE hardening_agent_collector_duration_seconds gauge"
    echo "hardening_agent_collector_duration_seconds ${duration}"
  } >"${tmp}"
  chmod 0644 "${tmp}"
  mv -f "${tmp}" "${TARGET_DIR}/hardening_agent_collector.prom"
}

cleanup() {
  # Remove any temporary file we may have left behind. A stray *.tmp in the
  # textfile directory is harmless, but a stray *.prom would be scraped.
  rm -f -- "${TMP_FILE:-}" 2>/dev/null || true
}
trap cleanup EXIT

main() {
  command -v "${AGENT_BIN}" >/dev/null 2>&1 ||
    die "agent binary not found at ${AGENT_BIN}"

  mkdir -p "${TARGET_DIR}"

  local start_ts end_ts duration rc=0
  start_ts="$(date +%s.%N)"

  # Write to a temporary file in the SAME directory, then rename. mv within one
  # filesystem is atomic, so a concurrent node_exporter scrape sees either the
  # old file or the new one -- never a partial write.
  TMP_FILE="$(mktemp "${TARGET_DIR}/.${METRIC_FILE}.XXXXXX")"

  if "${AGENT_BIN}" export --stdout >"${TMP_FILE}" 2>/dev/null; then
    rc=0
  else
    rc=$?
  fi

  end_ts="$(date +%s.%N)"
  duration="$(awk -v s="${start_ts}" -v e="${end_ts}" 'BEGIN {printf "%.3f", e - s}')"

  # Exit code 1 means "findings exist", which is a successful collection of a
  # non-compliant host. Only 2 and above indicate the agent itself failed.
  if (( rc >= 2 )); then
    log_error "agent export failed with exit code ${rc}; keeping the previous textfile"
    emit_scrape_status 0 "${duration}"
    exit 1
  fi

  if [[ ! -s "${TMP_FILE}" ]]; then
    log_error "agent produced no metrics; keeping the previous textfile"
    emit_scrape_status 0 "${duration}"
    exit 1
  fi

  chmod 0644 "${TMP_FILE}"
  mv -f "${TMP_FILE}" "${TARGET_FILE}"
  TMP_FILE=""

  emit_scrape_status 1 "${duration}"
  log_ok "wrote ${TARGET_FILE} in ${duration}s (agent exit ${rc})"
}

main "$@"
