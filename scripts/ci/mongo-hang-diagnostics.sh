#!/usr/bin/env bash
# mongo-hang-diagnostics.sh -- hang evidence of the Testcontainers MongoDB of the identity integration tests.
#
# Why: the Test step of azure-pipelines.yml sometimes ran into its step timeout without saying which test was in
# flight or what MongoDB waited on. This script records a filtered view of the running operations while the tests
# run, and prints it when the step fails or is cancelled, before the container is removed.
#
#   start  <dir> [max-minutes]   background sampler: every 60 s one heartbeat line, plus one line per operation that
#                                runs >= 20 s or waits for a lock. Ends by itself after max-minutes (default 45) or
#                                when <dir>/stop exists.
#   report <dir> <job-status>    stops the sampler; when <job-status> is not "Succeeded" prints the last samples and
#                                one fresh snapshot. Never fails the build.
#
# Output is filtered to what the evidence needs: op, ns, secs_running, waitingForLock, the lock modes (locks) and the
# resource names of lockStats. No command documents, no client addresses, no credentials. The credentials are never on
# the agent's command line or the build log: mongosh runs INSIDE the container and reads MONGO_INITDB_ROOT_* from the
# container's own environment (set there by the test fixture), so neither this script nor the build log ever holds them.
set -u

MODE="${1:-}"
DIR="${2:-}"
NAME_FILTER="${MONGO_DIAG_NAME_FILTER:-mongodb-identity-test-shared}"
INTERVAL="${MONGO_DIAG_INTERVAL_SECONDS:-60}"
# A starved mongod or a stuck docker daemon must not hold the agent: bound every exec
# (coreutils timeout exists on the CI agent; without it, e.g. on macOS, the exec is unbounded).
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout 60"; fi

# The JavaScript runs inside mongosh in the container. It prints one JSON line per notable operation and no other
# field of currentOp. "notable" = running >= 20 s or waiting for a lock; the idle-op count is the heartbeat.
read -r -d '' MONGO_JS <<'JS' || true
const ops = db.getSiblingDB('admin').aggregate([
  { $currentOp: { allUsers: true, idleConnections: false } },
  { $match: { active: true } }
]).toArray();
const notable = ops.filter(o => Number(o.secs_running || 0) >= 20 || o.waitingForLock === true);
print(JSON.stringify({ activeOps: ops.length, notable: notable.length }));
for (const o of notable.slice(0, 25)) {
  print(JSON.stringify({
    op: o.op, ns: o.ns, secs_running: Number(o.secs_running), waitingForLock: o.waitingForLock === true,
    locks: o.locks, lockStatsResources: Object.keys(o.lockStats || {})
  }));
}
JS

find_container() {
  # MONGO_DIAG_CONTAINER_ID pins one container (local use with several suites on one machine).
  if [ -n "${MONGO_DIAG_CONTAINER_ID:-}" ]; then
    docker ps -q --filter "id=${MONGO_DIAG_CONTAINER_ID}" 2>/dev/null | head -n 1
    return
  fi
  docker ps -q --filter "name=${NAME_FILTER}" 2>/dev/null | head -n 1
}

# Runs the JS in the container. The password stays inside the container shell ("$VAR" expands there).
sample_once() {
  local cid="$1"
  $TIMEOUT_CMD docker exec -i "$cid" sh -c 'mongosh --quiet -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --eval "$1"' sh "$MONGO_JS" 2>&1 \
    | grep -E '^\{' || echo '{"error":"mongosh produced no JSON (container gone, auth or shell problem)"}'
}

case "$MODE" in
  start)
    [ -n "$DIR" ] || { echo "usage: $0 start <dir> [max-minutes]"; exit 0; }
    MAX_MIN="${3:-45}"
    mkdir -p "$DIR"
    rm -f "$DIR/stop"
    : > "$DIR/samples.log"
    (
      end=$(( $(date +%s) + MAX_MIN * 60 ))
      while [ ! -f "$DIR/stop" ] && [ "$(date +%s)" -lt "$end" ]; do
        cid="$(find_container)"
        if [ -n "$cid" ]; then
          ts="$(date -u +%H:%M:%S)"
          sample_once "$cid" | sed "s/^/$ts /" >> "$DIR/samples.log"
        fi
        sleep "$INTERVAL"
      done
    ) >/dev/null 2>&1 &
    disown 2>/dev/null || true
    echo "Mongo hang sampler started (interval ${INTERVAL}s, max ${MAX_MIN} min, output $DIR/samples.log)"
    ;;
  report)
    [ -n "$DIR" ] || { echo "usage: $0 report <dir> <job-status>"; exit 0; }
    STATUS="${3:-}"
    touch "$DIR/stop" 2>/dev/null || true
    if [ "$STATUS" = "Succeeded" ] || [ "$STATUS" = "SucceededWithIssues" ]; then
      echo "Test step succeeded - no hang evidence needed."
      exit 0
    fi
    echo "=== Mongo hang evidence (job status: ${STATUS:-unknown}) ==="
    echo "--- samples recorded while the tests ran (last 40 lines; UTC time, then a JSON line) ---"
    if [ -s "$DIR/samples.log" ]; then tail -n 40 "$DIR/samples.log"; else echo "(no samples: container never seen or sampler did not run)"; fi
    cid="$(find_container)"
    if [ -n "$cid" ]; then
      echo "--- fresh snapshot now ---"
      sample_once "$cid"
    else
      echo "--- no running Testcontainers MongoDB left to ask (test host died before or container gone) ---"
    fi
    ;;
  *)
    echo "usage: $0 start <dir> [max-minutes] | report <dir> <job-status>"
    ;;
esac
exit 0
