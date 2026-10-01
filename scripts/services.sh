#!/usr/bin/env bash
# Starts (or stops) the three local services the stack needs: Neo4j, Redis and
# Postgres, on the same non-default ports as orchestrator/docker-compose.yml.
#
# Why this exists alongside that compose file: `docker compose` is a CLI plugin
# and is not always installed even where `docker` is -- on a plain
# docker-ce/podman install, `docker compose up -d` fails with
# "unknown shorthand flag: 'd'", which reads like a syntax error rather than a
# missing plugin. The compose file stays the source of truth for the service
# definitions; this script is the fallback that needs nothing but a container
# runtime, and it works with podman by setting CONTAINER_CLI=podman.
#
#   ./scripts/services.sh up       # start, wait until each is answering
#   ./scripts/services.sh down     # stop and remove (volumes survive)
#   ./scripts/services.sh status
#   ./scripts/services.sh reset    # down, then delete the volumes too
set -euo pipefail

CLI="${CONTAINER_CLI:-docker}"
command -v "$CLI" >/dev/null || {
  echo "no '$CLI' on PATH; set CONTAINER_CLI=podman if that is what you have" >&2
  exit 1
}

NEO4J_PASSWORD="${NEO4J_PASSWORD:-memoraidev}"
PG_PASSWORD="${POSTGRES_PASSWORD:-memoraidev}"

up() {
  # --restart unless-stopped so a laptop reboot does not look like a broken
  # checkout the next morning.
  run_if_absent memorai-neo4j \
    -p 127.0.0.1:7688:7687 -p 127.0.0.1:7475:7474 \
    -e "NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}" \
    -e "NEO4J_server_memory_heap_max__size=512M" \
    -v memorai-neo4j-data:/data \
    neo4j:5.26-community

  run_if_absent memorai-redis \
    -p 127.0.0.1:6380:6379 \
    redis:7-alpine

  # The gateway's sealed OAuth refresh-token store. The orchestrator is
  # deliberately given no credentials for it; nothing in Python reads these rows.
  run_if_absent memorai-postgres \
    -p 127.0.0.1:5435:5432 \
    -e "POSTGRES_USER=memorai" \
    -e "POSTGRES_PASSWORD=${PG_PASSWORD}" \
    -e "POSTGRES_DB=memorai" \
    -v memorai-postgres-data:/var/lib/postgresql/data \
    postgres:16-alpine

  wait_for_port 7688 "neo4j (bolt)"
  wait_for_port 6380 "redis"
  wait_for_port 5435 "postgres"
  echo
  echo "Neo4j browser: http://127.0.0.1:7475  (neo4j / ${NEO4J_PASSWORD})"
  status
}

run_if_absent() {
  local name="$1"; shift
  if "$CLI" ps --format '{{.Names}}' | grep -qx "$name"; then
    echo "$name already running"
    return
  fi
  if "$CLI" ps -a --format '{{.Names}}' | grep -qx "$name"; then
    echo "starting existing $name"
    "$CLI" start "$name" >/dev/null
    return
  fi
  echo "creating $name"
  "$CLI" run -d --name "$name" --restart unless-stopped "$@" >/dev/null
}

# Neo4j in particular takes a while on a cold start, and a pytest run against a
# half-started database skips rather than fails -- which looks like everything
# passing. Waiting here is what makes `services.sh up && pytest` honest.
wait_for_port() {
  local port="$1" label="$2"
  printf 'waiting for %s on :%s' "$label" "$port"
  for _ in $(seq 1 120); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- || true
      printf ' ok\n'
      return 0
    fi
    printf '.'
    sleep 1
  done
  printf ' TIMED OUT\n'
  echo "  check logs: $CLI logs memorai-${label%% *}" >&2
  return 1
}

down() {
  for name in memorai-neo4j memorai-redis memorai-postgres; do
    "$CLI" rm -f "$name" >/dev/null 2>&1 && echo "removed $name" || true
  done
}

reset() {
  down
  for volume in memorai-neo4j-data memorai-postgres-data; do
    "$CLI" volume rm "$volume" >/dev/null 2>&1 && echo "deleted volume $volume" || true
  done
}

status() {
  "$CLI" ps --filter name=memorai- --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' ||
    echo "(none running)"
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  reset) reset ;;
  status) status ;;
  *) echo "usage: $0 {up|down|reset|status}" >&2; exit 1 ;;
esac
