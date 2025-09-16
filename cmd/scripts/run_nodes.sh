#!/usr/bin/env bash
set -euo pipefail

# --- Defaults you can tweak ---
SESSION_NAME="nodes"     # all windows live inside this tmux session
BIND_IP="10.110.11.137"
HTTP_IP="10.110.11.137"
HTTP_PORT="9001"
CHAIN_ID="iotnet-main"
PNET_KEY="swarm.key"
MDNS="true"
STATS="5s"
LOG_LEVEL="info"
LOG_FORMAT="json"
CELL_MIN_DEVICES="2"

BASE_DATA_DIR=".dataA"   # Per-window dirs: .dataA-1, .dataA-2, ...

usage() {
  cat <<EOF
Usage: $(basename "$0") -n <count> [--clean] [--session <name>]

  -n, --count <count>   Number of tmux windows to start (required)
      --clean           Delete all per-window data dirs before starting (default: off)
      --session <name>  tmux session name to use (default: ${SESSION_NAME})

Notes:
  - Creates ONE tmux session with N windows.
  - Only window #1 passes -http ${HTTP_IP}:${HTTP_PORT}; others do not expose HTTP.
  - Each window uses its own -data-dir: ${BASE_DATA_DIR}-<i>
  - Nodes bind to ${BIND_IP} and use -port 0 for their internal listen port.
EOF
  exit 1
}

COUNT=""
CLEAN="false"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--count)
      COUNT="${2:-}"; shift 2 ;;
    --clean)
      CLEAN="true"; shift ;;
    --session)
      SESSION_NAME="${2:-}"; shift 2 ;;
    -h|--help)
      usage ;;
    *)
      echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "${COUNT}" ]] && { echo "Error: -n/--count is required."; usage; }

# --- Clean data dirs if requested ---
if [[ "${CLEAN}" == "true" ]]; then
  echo "[*] Cleaning data dirs..."
  for (( i=1; i<=COUNT; i++ )); do
    DIR="${BASE_DATA_DIR}-${i}"
    if [[ -d "${DIR}" ]]; then
      rm -rf -- "${DIR}"
      echo "  removed ${DIR}"
    fi
  done
fi

# --- Build a function to create the node command for window i ---
build_cmd() {
  local idx="$1"
  local data_dir="${BASE_DATA_DIR}-${idx}"

  local http_arg=()
  if [[ "${idx}" -eq 1 ]]; then
    http_arg=( -http "${HTTP_IP}:${HTTP_PORT}" )
  fi

  # Compose command array
  local cmd=( go run ./cmd/node
    -chain-id "${CHAIN_ID}"
    -bind "${BIND_IP}"
    -port 0
    "${http_arg[@]}"
    -pnet "${PNET_KEY}"
    -mdns="${MDNS}"
    -data-dir "${data_dir}"
    -stats "${STATS}"
    -log-level "${LOG_LEVEL}"
    -log-format "${LOG_FORMAT}"
    -cell-min-devices "${CELL_MIN_DEVICES}"
  )

  # Return a safely-quoted single string
  printf "%q " "${cmd[@]}"
}

# --- Ensure tmux is present ---
if ! command -v tmux >/dev/null 2>&1; then
  echo "Error: tmux not found in PATH." >&2
  exit 1
fi

# --- Create session (detached) with window #1 ---
FIRST_CMD="$(build_cmd 1)"

if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
  echo "[*] Using existing tmux session: ${SESSION_NAME}"
  # Create/replace window 1 if it doesn't exist; else start a new one named w1-<ts>
  if ! tmux list-windows -t "${SESSION_NAME}" -F '#I' | grep -qx '1'; then
    tmux new-window -t "${SESSION_NAME}" -n "w1" "bash -lc '${FIRST_CMD}'"
  else
    # If window 1 exists, create a fresh window w1 and run there to avoid clobbering
    tmux new-window -t "${SESSION_NAME}" -n "w1" "bash -lc '${FIRST_CMD}'"
  fi
else
  echo "[*] Creating tmux session ${SESSION_NAME} with window #1"
  tmux new-session -d -s "${SESSION_NAME}" -n "w1" "bash -lc '${FIRST_CMD}'"
fi

# --- Create windows #2..N ---
for (( i=2; i<=COUNT; i++ )); do
  WIN_NAME="w${i}"
  CMD_STR="$(build_cmd "${i}")"
  tmux new-window -t "${SESSION_NAME}" -n "${WIN_NAME}" "bash -lc '${CMD_STR}'"
  echo "[*] started window ${WIN_NAME} -> data dir ${BASE_DATA_DIR}-${i}"
done

echo
echo "[✓] Launched ${COUNT} window(s) in tmux session '${SESSION_NAME}'."
echo "    Attach:      tmux attach -t ${SESSION_NAME}"
echo "    List wins:   tmux list-windows -t ${SESSION_NAME}"
echo "    Kill sess:   tmux kill-session -t ${SESSION_NAME}"