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

NEO4J_PASSWORD="${NEO4J_PASSWORD:-kleosdev}"
PG_PASSWORD="${POSTGRES_PASSWORD:-kleosdev}"

# The containers, the volumes, the Postgres role and the Neo4j password were all
# named `memorai` before the rename. None of those can be renamed in place: the
# Neo4j password lives inside its own data directory, and the Postgres role and
# database name were fixed when the volume was first initialised. So a checkout
# that predates the rename has containers this script will no longer find, holding
# credentials it no longer uses -- and the failure, left alone, is an
# authentication error against a database that looks like it is running fine.
#
# Said out loud rather than worked around, and with the non-destructive path
# first: change the stored credentials, then replace the containers while keeping
# the volumes, which loses no node and no row.
#
# Renaming the container is *not* enough, and finding that out cost a while. A
# container's environment and its healthcheck are fixed at creation and `docker
# rename` changes neither, so a compose-created Neo4j keeps running
# `cypher-shell -u neo4j -p <old password>` every five seconds. Neo4j rate-limits
# repeated authentication failures, so the healthcheck then locks out *correct*
# credentials in windows long enough to span a whole test run -- which reads as a
# wrong password, intermittently, forever.
#
# A deployment holding anything real needs none of this: the SQL in
# `gateway/src/store/` renames the tables in place and `storage/migrations.py`
# does the same for the Neo4j constraints and indexes.
check_for_pre_rename_containers() {
  local stale=()
  for name in memorai-neo4j memorai-redis memorai-postgres; do
    if "$CLI" ps -a --format '{{.Names}}' | grep -qx "$name"; then
      stale+=("$name")
    fi
  done
  [ ${#stale[@]} -eq 0 ] && return 0

  echo "Found containers from before the Kleos rename: ${stale[*]}" >&2
  echo >&2
  echo "They hold a 'memorai' Postgres role and Neo4j password this script no longer" >&2
  echo "uses. Nothing has to be deleted: the data lives in named volumes, and a" >&2
  echo "container can be replaced without touching them." >&2
  echo >&2
  echo "  # 1. change the stored credentials, using the old ones" >&2
  echo "  $CLI exec memorai-neo4j cypher-shell -u neo4j -p memoraidev \\" >&2
  echo "    \"ALTER CURRENT USER SET PASSWORD FROM 'memoraidev' TO 'kleosdev'\"" >&2
  echo "  $CLI exec memorai-postgres psql -U memorai -d memorai \\" >&2
  echo "    -c \"CREATE ROLE kleos LOGIN SUPERUSER PASSWORD 'kleosdev'\" \\" >&2
  echo "    -c \"CREATE DATABASE kleos OWNER kleos\"" >&2
  echo >&2
  echo "  # 2. remove the containers, keeping the volumes, and let this script" >&2
  echo "  #    recreate them with the new names and credentials" >&2
  echo "  $CLI rm -f ${stale[*]}" >&2
  echo "  $0 up" >&2
  echo >&2
  echo "Recreating rather than renaming, and this is the part that bites: a" >&2
  echo "container's environment AND ITS HEALTHCHECK are fixed when it is created." >&2
  echo "\`$CLI rename\` changes neither. A compose-created Neo4j runs" >&2
  echo "\`cypher-shell -u neo4j -p <old>\` every five seconds, so after changing the" >&2
  echo "password the healthcheck fails forever -- and because Neo4j rate-limits" >&2
  echo "repeated authentication failures, the database then rejects correct" >&2
  echo "credentials too, in windows long enough to span a whole test run. It looks" >&2
  echo "exactly like a wrong password. Replacing the container is what actually" >&2
  echo "ends it; \`$CLI restart\` only clears the lockout until the next healthcheck." >&2
  echo >&2
  echo "If this script created the originals, the volumes are kleos-*-data and are" >&2
  echo "reused as they are. If compose did, they are orchestrator_*-data and the new" >&2
  echo "containers will start empty unless you mount them explicitly:" >&2
  echo >&2
  echo "  $CLI run -d --name kleos-neo4j -p 127.0.0.1:7688:7687 \\" >&2
  echo "    -e NEO4J_AUTH=neo4j/kleosdev -v orchestrator_neo4j-data:/data \\" >&2
  echo "    neo4j:5.26-community" >&2
  echo >&2
  echo "Or start clean, if the contents are expendable (Neo4j rebuilds by" >&2
  echo "re-ingesting and the token rows are mock consents):" >&2
  echo >&2
  echo "    $CLI rm -f ${stale[*]}" >&2
  echo "    $CLI volume rm memorai-neo4j-data memorai-postgres-data" >&2
  echo "    $0 up" >&2
  echo >&2
  echo "Set KLEOS_IGNORE_OLD_CONTAINERS=1 to start the new ones alongside them;" >&2
  echo "they bind the same ports, so one set has to be stopped either way." >&2
  return 1
}

up() {
  if [ -z "${KLEOS_IGNORE_OLD_CONTAINERS:-}" ]; then
    check_for_pre_rename_containers || exit 1
  fi

  # --restart unless-stopped so a laptop reboot does not look like a broken
  # checkout the next morning.
  run_if_absent kleos-neo4j \
    -p 127.0.0.1:7688:7687 -p 127.0.0.1:7475:7474 \
    -e "NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}" \
    -e "NEO4J_server_memory_heap_max__size=512M" \
    -v kleos-neo4j-data:/data \
    neo4j:5.26-community

  run_if_absent kleos-redis \
    -p 127.0.0.1:6380:6379 \
    redis:7-alpine

  # The gateway's sealed OAuth refresh-token store. The orchestrator is
  # deliberately given no credentials for it; nothing in Python reads these rows.
  run_if_absent kleos-postgres \
    -p 127.0.0.1:5435:5432 \
    -e "POSTGRES_USER=kleos" \
    -e "POSTGRES_PASSWORD=${PG_PASSWORD}" \
    -e "POSTGRES_DB=kleos" \
    -v kleos-postgres-data:/var/lib/postgresql/data \
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
  echo "  check logs: $CLI logs kleos-${label%% *}" >&2
  return 1
}

down() {
  for name in kleos-neo4j kleos-redis kleos-postgres; do
    "$CLI" rm -f "$name" >/dev/null 2>&1 && echo "removed $name" || true
  done
}

reset() {
  down
  for volume in kleos-neo4j-data kleos-postgres-data; do
    "$CLI" volume rm "$volume" >/dev/null 2>&1 && echo "deleted volume $volume" || true
  done
}

status() {
  "$CLI" ps --filter name=kleos- --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' ||
    echo "(none running)"
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  reset) reset ;;
  status) status ;;
  *) echo "usage: $0 {up|down|reset|status}" >&2; exit 1 ;;
esac
