#!/usr/bin/env bash
# Kleos, as a personal install: one command up, one command down.
#
#   ./scripts/kleos.sh up        # everything, in order, with a preflight
#   ./scripts/kleos.sh status    # what is running and what it can do
#   ./scripts/kleos.sh doctor    # the preflight on its own, changing nothing
#   ./scripts/kleos.sh enrol     # become the owner of this install
#   ./scripts/kleos.sh agent     # a grant, and the line to connect an agent
#   ./scripts/kleos.sh down      # stop what this started
#   ./scripts/kleos.sh logs
#
# There were three scripts before this and none of them was "run Kleos".
# `run_local.sh` starts the enclave and gateway, `services.sh` starts the
# containers, and `hands_on.sh` starts the orchestrator *and mints two demo
# grants* -- so the way to run a personal install was a demo script, which is
# how `hands_on.sh` ended up being the thing that needed ATTESTATION_ALLOW_MOCK
# before an ordinary write would work.
#
# The preflight is the other half. Two failures cost real time while building
# this and neither announced itself:
#
#   * a stale orchestrator already holding :8090, so a new one fails to bind,
#     exits, and every request is silently served by the *old* build;
#   * ENCRYPT_CONTENT_AT_REST on, which makes the briefing answer 409 -- correct
#     (ADR 0024) and baffling if you did not know the setting was on.
#
# Both are checked here rather than left to be rediscovered.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GATEWAY_PORT="${GATEWAY_PORT:-8080}"
ENCLAVE_PORT="${ENCLAVE_PORT:-4000}"
ORCH_PORT="${ORCHESTRATOR_PORT:-8090}"
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
ORCH_URL="http://127.0.0.1:$ORCH_PORT"
PY="$ROOT_DIR/orchestrator/.venv/bin/python"
DEVICE_KEY="${KLEOS_DEVICE_KEY:-$ROOT_DIR/.local/owner.key}"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mfail\033[0m  %s\n' "$1"; }

# `|| true` because `pipefail` is on and a free port means grep finds nothing,
# which would otherwise abort the preflight at the first port that is *fine*.
port_pid() {
  ss -ltnp 2>/dev/null | grep -F ":$1 " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1 || true
}
alive()    { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

# Whether the three backing services answer, whoever started them.
#
# A TCP connect and nothing more: a Cypher query would need credentials this
# script has no business holding, and "the port answers" is what distinguishes
# "start the containers" from "do not".
services_ready() {
  local neo4j_port="${NEO4J_PORT:-7688}"
  local redis_port="${REDIS_PORT:-6380}"
  for port in "$neo4j_port" "$redis_port"; do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 1
  done
}

# ---------------------------------------------------------------- doctor

doctor() {
  local failures=0

  bold "Prerequisites"
  if command -v docker >/dev/null || command -v podman >/dev/null; then
    ok "a container runtime"
  else
    bad "no docker or podman: Neo4j, Redis and Postgres run in containers"
    failures=$((failures + 1))
  fi
  if [ -x "$PY" ]; then
    ok "the orchestrator venv"
  else
    bad "no venv at orchestrator/.venv -- python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'"
    failures=$((failures + 1))
  fi
  if command -v cargo >/dev/null; then ok "cargo"; else
    bad "no cargo: the enclave, gateway and kleos-device are Rust"
    failures=$((failures + 1))
  fi

  bold "Ports"
  # The stale-orchestrator trap. A port held by something this script did not
  # start is the dangerous case: the new process exits and the old one keeps
  # answering, so every change appears to have no effect.
  for spec in "$ENCLAVE_PORT:enclave:.local/enclave.pid" \
              "$GATEWAY_PORT:gateway:.local/gateway.pid" \
              "$ORCH_PORT:orchestrator:.local/orchestrator.pid"; do
    local port name pidfile holder
    port="${spec%%:*}"; name="$(echo "$spec" | cut -d: -f2)"; pidfile="$(echo "$spec" | cut -d: -f3)"
    holder="$(port_pid "$port")"
    if [ -z "$holder" ]; then
      ok ":$port free (for the $name)"
    elif [ -f "$pidfile" ] && [ "$holder" = "$(cat "$pidfile")" ]; then
      ok ":$port held by this install's $name (pid $holder)"
    else
      bad ":$port held by pid $holder, which this install did not start. A new $name \
will fail to bind and exit, and that one keeps answering. Stop it: kill $holder"
      failures=$((failures + 1))
    fi
  done

  bold "Settings"
  if [ "${ENCRYPT_CONTENT_AT_REST:-0}" = "1" ]; then
    warn "ENCRYPT_CONTENT_AT_REST=1: the briefing will answer 409. Content is sealed \
and brief_before_acting writes its advisories from claim text, which then exists only \
inside the enclave (ADR 0024). query_memory still works and returns a sealed answer."
  else
    ok "content is not sealed at rest; the briefing works"
  fi
  if [ "${ENCLAVE_MODE:-mock}" = "mock" ]; then
    warn "mock enclave: sealing is a reversible XOR and attestations are stubs. Correct \
for a personal install -- you are the operator -- but do not read it as confidentiality \
from anyone."
  fi

  bold "Model"
  if [ -x "$PY" ]; then
    "$PY" - <<'EOF' || true
import sys
sys.path.insert(0, "orchestrator/src")
try:
    from orchestrator import models
    from orchestrator.config import get_settings
except Exception as exc:  # the venv may predate this module
    print(f"  \033[33mwarn\033[0m  could not read the model settings: {exc}")
    sys.exit(0)

status = models.describe(get_settings())
mark = "\033[32mok\033[0m   " if status.configured else "\033[33mwarn\033[0m "
print(f"  {mark} {status.summary}")
if not status.configured:
    print("         keyless: record_decision, brief_before_acting, query_memory, why_this_shifted")
    print("         needs a model: ingesting a source (silently writes nothing without one)")
    print("         set EXTRACTOR=llm and LLM_BASE_URL, or run a local model")
EOF
  fi

  bold "Owner"
  if [ -f "$ROOT_DIR/.local/enrolment-code" ]; then
    warn "nobody has enrolled yet: ./scripts/kleos.sh enrol"
  elif [ -f "$DEVICE_KEY" ]; then
    ok "enrolled, key at ${DEVICE_KEY#$ROOT_DIR/}"
  else
    warn "this install has an owner, but no key at ${DEVICE_KEY#$ROOT_DIR/} on this machine"
  fi

  [ "$failures" -eq 0 ] || { echo; echo "$failures blocking problem(s) above."; return 1; }
}

# -------------------------------------------------------------------- up

up() {
  doctor || { echo; echo "Refusing to start. Fix the above, or run 'doctor' again."; exit 1; }

  echo
  bold "Starting"
  # Reachability first, and `services.sh up` only if something is missing.
  # Three reasons, and the third is the one that bit: it is idempotent, it
  # tolerates a Neo4j you run yourself, and `services.sh` deliberately refuses
  # to start when it finds containers from before the rename -- which is
  # correct advice and the wrong outcome when those containers are up and
  # answering.
  if services_ready; then
    ok "Neo4j, Redis, Postgres already answering"
  else
    ./scripts/services.sh up >/dev/null || {
      bad "the backing services are not reachable and services.sh could not start them."
      echo "       Run ./scripts/services.sh up on its own -- it explains what it found."
      exit 1
    }
    ok "Neo4j, Redis, Postgres"
  fi

  cargo build -q -p enclave -p gateway -p device
  ok "built the Rust binaries"

  # run_local.sh owns the enclave and gateway, including the environment they
  # need; duplicating it here is how the two drift.
  if alive .local/enclave.pid && alive .local/gateway.pid; then
    ok "enclave and gateway already running"
  else
    ./scripts/run_local.sh < /dev/null >/dev/null 2>&1
    ok "enclave on :$ENCLAVE_PORT, gateway on :$GATEWAY_PORT"
  fi

  if alive .local/orchestrator.pid; then
    ok "orchestrator already running"
  else
    mkdir -p .local
    # Two things in this shape, and both were bugs first.
    #
    # `exec` inside the subshell, so the pid recorded is python's. Written the
    # obvious way -- `( cd X && cmd & )` -- bash backgrounds the whole `&&`
    # list in a subshell, `$!` is that subshell, and python is its child: `down`
    # then kills the subshell and leaves an orphan holding :8090. Which is the
    # stale-orchestrator trap this script's own preflight exists to catch, and
    # it caught it here.
    #
    # `< /dev/null` and `nohup`, so the daemons do not keep this script's
    # stdout open. Without it `kleos.sh up | tail` never reaches
    # end-of-file and hangs after everything has already started, which looks
    # exactly like a service failing to come up.
    ( cd orchestrator && MCP_HTTP_ENABLED=1 exec nohup "$PY" -m orchestrator.api \
        < /dev/null > "$ROOT_DIR/.local/orchestrator.log" 2>&1 ) &
    echo $! > "$ROOT_DIR/.local/orchestrator.pid"
    ( cd orchestrator && exec nohup "$PY" -m orchestrator.jobs.worker \
        < /dev/null > "$ROOT_DIR/.local/worker.log" 2>&1 ) &
    echo $! > "$ROOT_DIR/.local/worker.pid"
    for _ in $(seq 1 60); do
      curl -sf "$ORCH_URL/health" >/dev/null 2>&1 && break
      sleep 0.5
    done
    curl -sf "$ORCH_URL/health" >/dev/null 2>&1 \
      && ok "orchestrator on :$ORCH_PORT, worker running" \
      || { bad "the orchestrator did not come up; see .local/orchestrator.log"; exit 1; }
  fi

  echo
  status
}

# ---------------------------------------------------------------- status

status() {
  bold "Running"
  for spec in "enclave:.local/enclave.pid" "gateway:.local/gateway.pid" \
              "orchestrator:.local/orchestrator.pid" "worker:.local/worker.pid"; do
    local name pidfile
    name="${spec%%:*}"; pidfile="${spec#*:}"
    if alive "$pidfile"; then ok "$name (pid $(cat "$pidfile"))"; else warn "$name is not running"; fi
  done

  echo
  bold "Next"
  if [ -f "$ROOT_DIR/.local/enrolment-code" ]; then
    echo "  ./scripts/kleos.sh enrol          become the owner of this install"
  else
    echo "  ./scripts/kleos.sh agent          a grant, and the line to connect an agent"
  fi
  echo "  $ORCH_URL/ui             the dashboard"
  echo "  ./scripts/kleos.sh doctor         what works and what does not"
}

# ----------------------------------------------------------------- enrol

enrol() {
  [ -f "$ROOT_DIR/.local/enrolment-code" ] || {
    echo "This install already has an owner. To replace it, delete the Neo4j volume" >&2
    echo "and the gateway's device keys, then restart -- a new code is written on boot." >&2
    exit 1
  }
  [ -f "$DEVICE_KEY" ] || ./target/debug/kleos-device keygen --key "$DEVICE_KEY" >/dev/null
  local body
  body="$(./target/debug/kleos-device enrol --key "$DEVICE_KEY" \
    --code "$(cat "$ROOT_DIR/.local/enrolment-code")" --label "$(hostname)")"
  curl -sS -X POST "$GATEWAY_URL/auth/local/enrol" \
    -H 'content-type: application/json' --data "$body" \
    | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print("owner:", d["owner_id"]); print("device:", d["key_id"])'
  echo
  echo "Your key is at ${DEVICE_KEY#$ROOT_DIR/}. It signs every grant you issue and is"
  echo "the only thing that can: losing it means re-enrolling, and nothing else can mint"
  echo "a grant on your behalf (ADR 0011)."
}

session_token() {
  ./target/debug/kleos-device sign-session --key "$DEVICE_KEY" \
    | curl -sS -X POST "$GATEWAY_URL/auth/local/session" \
        -H 'content-type: application/json' --data @- \
    | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])'
}

# ----------------------------------------------------------------- agent

agent() {
  [ -f "$DEVICE_KEY" ] || { echo "no owner key; run ./scripts/kleos.sh enrol first" >&2; exit 1; }
  local agent_id="${1:-claude-code}"
  local session owner ttl=28800
  session="$(session_token)"
  owner="$("$PY" -c '
import base64, json, sys
payload = sys.argv[1].split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.loads(base64.urlsafe_b64decode(payload))["owner_id"])' "$session")"

  # Registered under the owner session, which is the path the dashboard uses.
  # One key per agent is a convention rather than an enforcement -- revoking a
  # key invalidates every grant it signed, so sharing one across agents means
  # cutting one off cuts them all off.
  local scope
  scope="$("$PY" - "$owner" "$agent_id" <<'EOF'
import json, sys
owner, agent = sys.argv[1], sys.argv[2]
print(json.dumps({
    "agent_id": agent, "owner_id": owner,
    "sources": ["mock", "agent", "text"],
    "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
    "max_sensitivity": "confidential",
    "may_write": True, "write_sources": ["agent"],
    "memory_kinds": ["episodic", "procedural", "tacit"],
}))
EOF
)"
  local token
  token="$(echo "$scope" | ./target/debug/kleos-device sign --key "$DEVICE_KEY" --scope - --ttl-secs "$ttl")"

  bold "A grant for '$agent_id', valid ${ttl}s"
  echo
  echo "  claude mcp add --transport http kleos $ORCH_URL/mcp/"
  echo
  echo "The trailing slash matters: the app is mounted at /mcp and the endpoint inside it"
  echo "is \"/\", so /mcp redirects and some clients drop the session header."
  echo
  echo "Then paste this to the agent:"
  echo
  echo "  You have the kleos MCP tools. My grant token is:"
  echo "  $token"
  echo "  Pass it as grant_token on every kleos call. Before advising me, call"
  echo "  brief_before_acting with what I am about to do."
}

# ------------------------------------------------------------------ down

down() {
  for pidfile in .local/orchestrator.pid .local/worker.pid .local/gateway.pid .local/enclave.pid; do
    if alive "$pidfile"; then
      kill "$(cat "$pidfile")" 2>/dev/null && ok "stopped ${pidfile#.local/}"
      rm -f "$pidfile"
    fi
  done

  # Then check the ports actually came free, because a pid file is a claim
  # about what was started and the port is the fact. Anything still holding one
  # is what the next `up` would silently inherit.
  sleep 1
  local leftover=0
  for spec in "$ENCLAVE_PORT:enclave" "$GATEWAY_PORT:gateway" "$ORCH_PORT:orchestrator"; do
    local port name holder
    port="${spec%%:*}"; name="${spec#*:}"
    holder="$(port_pid "$port")"
    if [ -n "$holder" ]; then
      warn "$name's port :$port is still held by pid $holder. Not something this \
script started, or something that outlived it: kill $holder"
      leftover=1
    fi
  done
  [ "$leftover" -eq 0 ] && ok "every port released"

  echo "The containers are still up; ./scripts/services.sh down stops them, and your"
  echo "memory lives in their volumes."
}

case "${1:-}" in
  up)     up ;;
  down)   down ;;
  status) status ;;
  doctor) doctor ;;
  enrol|enroll) enrol ;;
  agent)  shift; agent "${1:-claude-code}" ;;
  logs)   tail -n 40 -f .local/orchestrator.log .local/gateway.log ;;
  *)
    echo "usage: ./scripts/kleos.sh <up|down|status|doctor|enrol|agent [id]|logs>"
    exit 1
    ;;
esac
