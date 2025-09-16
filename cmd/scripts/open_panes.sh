#!/usr/bin/env bash
set -euo pipefail

# ---- Defaults ----
SESSION_NAME="nodes"
WINDOW_BASE="nodes"
BIND_IP="10.110.11.137"
HTTP_IP="10.110.11.137"
HTTP_PORT_START=9001
CHAIN_ID="iotnet-main"
PNET_KEY="swarm.key"
MDNS="true"
STATS="5s"
LOG_LEVEL="info"
LOG_FORMAT="json"
CELL_MIN_DEVICES="2"
BASE_PREFIX="data"       # dataA, dataB, ...

LAYOUT="tiled"

usage() {
  cat <<EOF
Usage: $(basename "$0") -n <count> [--clean] [--session <name>] [--layout <layout>]

  -n, --count <count>   Number of panes to start (required)
      --clean           Delete all per-pane data dirs before starting (default: off)
      --session <name>  tmux session name (default: ${SESSION_NAME})
      --layout <lay>    tmux layout after split (default: ${LAYOUT})

Notes:
  - Creates ONE tmux session and ONE window with N panes.
  - Each pane gets its own -data-dir: ${BASE_PREFIX}A, ${BASE_PREFIX}B, ...
  - Each pane gets a unique -http port: ${HTTP_IP}:9001, :9002, ...
EOF
  exit 1
}

COUNT=""
CLEAN="false"

# ---- Parse args ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--count) COUNT="${2:-}"; shift 2 ;;
    --clean)    CLEAN="true"; shift ;;
    --session)  SESSION_NAME="${2:-}"; shift 2 ;;
    --layout)   LAYOUT="${2:-}"; shift 2 ;;
    -h|--help)  usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "${COUNT}" ]] && { echo "Error: -n/--count is required."; usage; }
[[ "${COUNT}" =~ ^[0-9]+$ ]] || { echo "Error: count must be an integer."; exit 1; }
(( COUNT >= 1 )) || { echo "Error: count must be >= 1."; exit 1; }

# ---- Ensure tmux ----
command -v tmux >/dev/null 2>&1 || { echo "Error: tmux not found."; exit 1; }

# ---- Alphabetic name helper ----
alpha_name() {
  local idx="$1"  # 1-based
  local n=$((idx-1))
  local name=""
  while true; do
    name="$(printf \\$(printf '%03o' $((65 + (n % 26)))))${name}"
    (( n = n / 26 - 1 ))
    (( n < 0 )) && break
  done
  echo "${BASE_PREFIX}${name}"
}

# ---- Clean dirs ----
if [[ "${CLEAN}" == "true" ]]; then
  echo "[*] Cleaning data dirs..."
  for (( i=1; i<=COUNT; i++ )); do
    DIR="$(alpha_name $i)"
    [[ -d "${DIR}" ]] && { rm -rf -- "${DIR}"; echo "  removed ${DIR}"; }
  done
fi

# ---- Build node command ----
build_cmd() {
  local idx="$1"
  local data_dir="$(alpha_name $idx)"
  local http_port=$((HTTP_PORT_START + idx - 1))

  local cmd=( go run ./cmd/node
    -chain-id "${CHAIN_ID}"
    -bind "${BIND_IP}"
    -port 0
    -http "${HTTP_IP}:${http_port}"
    -pnet "${PNET_KEY}"
    -mdns="${MDNS}"
    -data-dir "${data_dir}"
    -stats "${STATS}"
    -log-level "${LOG_LEVEL}"
    -log-format "${LOG_FORMAT}"
    -cell-min-devices "${CELL_MIN_DEVICES}"
  )
  printf "%q " "${cmd[@]}"
}

# ---- Create/reuse session ----
if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
  echo "[*] Using existing tmux session: ${SESSION_NAME}"
else
  echo "[*] Creating tmux session: ${SESSION_NAME}"
  tmux new-session -d -s "${SESSION_NAME}" -n "bootstrap" "bash -lc 'exec bash'"
fi

WIN_NAME="${WINDOW_BASE}-$(date +%H%M%S)"
WIN_ID="$(tmux new-window -P -F "#{window_id}" -t "${SESSION_NAME}" -n "${WIN_NAME}" "bash -lc 'exec bash'")"
tmux select-window -t "${WIN_ID}"

# ---- First pane ----
FIRST_CMD="$(build_cmd 1)"
tmux send-keys -t "${WIN_ID}" "bash -lc '${FIRST_CMD}'" C-m

# ---- Other panes ----
for (( i=2; i<=COUNT; i++ )); do
  CMD_STR="$(build_cmd "${i}")"
  if (( i % 2 == 0 )); then
    tmux split-window -t "${WIN_ID}" -h "bash -lc '${CMD_STR}'"
  else
    tmux split-window -t "${WIN_ID}" -v "bash -lc '${CMD_STR}'"
  fi
  tmux select-layout -t "${WIN_ID}" tiled >/dev/null 2>&1 || true
done

tmux select-layout -t "${WIN_ID}" "${LAYOUT}" >/dev/null 2>&1 || tmux select-layout -t "${WIN_ID}" tiled

# ---- Summary ----
echo
echo "[✓] Launched ${COUNT} pane(s) in tmux session '${SESSION_NAME}', window '${WIN_NAME}'."
for (( i=1; i<=COUNT; i++ )); do
  dir="$(alpha_name $i)"
  port=$((HTTP_PORT_START + i - 1))
  echo "    Pane $i -> ${dir}, http ${HTTP_IP}:${port}"
done
echo "    Attach: tmux attach -t ${SESSION_NAME}"