#!/usr/bin/env bash
# Tests for scripts/identity-bootstrap-seed-check.sh. No cluster needed.
#   1. the write guard passes the shipped JavaScript and refuses each planted write-capable call -- and then never
#      reaches kubectl;
#   2. with a fake kubectl: output contract (TSV, exit codes 0/2/1), the MongoDB password reaching mongosh on stdin only
#      (never in an argument, never in the output), from the cluster secret or from --password-file;
#   3. the inventory JavaScript against an in-memory MongoDB mock (node, *.inventory.test.mjs).
# Run: bash scripts/tests/identity-bootstrap-seed-check.test.sh   (needs bash, node)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
NAME="identity-bootstrap-seed-check"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/bootstrap-seed-check-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
PASSED=0
ok() { PASSED=$((PASSED + 1)); echo "ok - $*"; }
fail() { FAILED=$((FAILED + 1)); echo "not ok - $*"; }

copy_scripts() {
    mkdir -p "$1"
    cp "$SRC/$NAME.sh" "$SRC/$NAME.inventory.js" "$1/"
}

# Fake kubectl: get pods / get secret / exec. exec runs the command after "--" (the script's real in-pod runner)
# locally, with stdin passed through. Its argv is logged; the password must be in no argument.
# Fake mongosh: expects "--quiet --nodb <file>.js", checks that the password arrives on its stdin, logs the script it
# was given, then prints canned output chosen by FAKE_MODE (clean | findings | nodb | incomplete).
FAKEBIN="$TMP/bin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/kubectl" <<'FAKE'
#!/usr/bin/env bash
PW="fake-pw-0815"
echo "kubectl $*" >>"$FAKE_LOG"
for a in "$@"; do case "$a" in *"$PW"*) echo "PASSWORD-IN-ARGV" >>"$FAKE_LOG"; exit 9 ;; esac; done
case " $* " in
    *" get pods "*) printf 'pod/octo-mongodb-arb-0\npod/octo-mongodb-0\npod/octo-mongodb-1\n' ;;
    *" get secret "*) printf '%s' "$PW" | base64 ;;
    *" exec "*)
        while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
        shift
        exec "$@" ;;
    *) echo "unexpected kubectl call" >&2; exit 7 ;;
esac
FAKE
chmod +x "$FAKEBIN/kubectl"
cat >"$FAKEBIN/mongosh" <<'FAKE'
#!/usr/bin/env bash
PW="fake-pw-0815"
[ "$#" -eq 3 ] && [ "$1" = "--quiet" ] && [ "$2" = "--nodb" ] && [[ "$3" == *.js ]] || { echo "unexpected mongosh args: $*" >&2; exit 6; }
IFS= read -r line
[ "$line" = "$PW" ] || { echo "password not on stdin" >&2; exit 8; }
cat "$3" >>"$FAKE_LOG.js"
echo "CONN replicaSet=rs0 members=3"
printf 'SEED\tSystem.Identity.Bootstrap-1.10.0\t41\t23\n'
case "$FAKE_MODE" in
    findings)
        printf 'ROW\ttenanta\tentity\t660000000000000000000001\tSystem.Identity/Role\tMISSING\n'
        printf 'SUM\ttenanta\t40\t41\t660000000000000000000001\t-\t23\t23\t0\t0\n' ;;
    nodb) printf 'ROW\tgone\ttenant\t-\tdatabase gone\tNO-DATABASE\n' ;;
esac
printf 'SUM\toctosystem\t41\t41\t-\t-\t23\t23\t0\t0\n'
[ "$FAKE_MODE" = incomplete ] || echo "END"
exit 0
FAKE
chmod +x "$FAKEBIN/mongosh"

# run_fake <mode> <args...>: runs the real script against the fake kubectl; sets RC, OUT, ERR, LOG, JS.
run_fake() {
    local mode="$1"; shift
    export FAKE_MODE="$mode" FAKE_LOG="$TMP/kubectl-$mode.log"
    rm -f "$FAKE_LOG" "$FAKE_LOG.js"; touch "$FAKE_LOG" "$FAKE_LOG.js"
    set +e
    PATH="$FAKEBIN:$PATH" bash "$SRC/$NAME.sh" --context fake-ctx "$@" >"$TMP/out" 2>"$TMP/err"
    RC=$?
    set -e
    OUT="$(cat "$TMP/out")"; ERR="$(cat "$TMP/err")"; LOG="$(cat "$FAKE_LOG")"; JS="$(cat "$FAKE_LOG.js")"
}

# --- 1. write guard ------------------------------------------------------------------------------------------------
if bash "$SRC/$NAME.sh" --self-check 2>/dev/null; then ok "guard passes the shipped JavaScript"; else fail "guard refuses the shipped JavaScript"; fi

PLANTED=(
    'd.getCollection("RtEntity_SystemIdentityClient").insertOne({});'
    'd.getCollection("x").updateMany({}, {});'
    'd.getCollection("x").replaceOne({}, {});'
    'd.getCollection("x").deleteMany({});'
    'd.getCollection("x").remove({});'
    'd.getCollection("x").drop();'
    'd.dropDatabase();'
    'd.getCollection("x").createIndex({ a: 1 });'
    'd.getCollection("x").bulkWrite([]);'
    'd.getCollection("x").findOneAndUpdate({}, {});'
    'd.getCollection("x").aggregate([{ $out: "y" }]);'
    'const stage = { $merge: { into: "y" } };'
    'd.runCommand({ insert: "x", documents: [{}] });'
    'conn.adminCommand({ dropDatabase: 1 });'
    'd.getCollection("x")["insertOne"]({});'
    'eval("d.getCollection(1)");'
    'require("fs");'
    'd.changeUserPassword("u", "p");'
    'd.getCollection("x").ensureIndex({ a: 1 });'
    'rs.reconfig({});'
    'rs.stepDown();'
    'Reflect.get(d.getCollection("x"), "insertOne");'
    'const k = "insert" + "One"; d.getCollection("x")[k]({});'
    'globalThis.db;'
)
i=0
for call in "${PLANTED[@]}"; do
    i=$((i + 1))
    dir="$TMP/guard-$i"
    copy_scripts "$dir"
    printf '%s\n' "$call" >>"$dir/$NAME.inventory.js"
    if bash "$dir/$NAME.sh" --self-check >/dev/null 2>&1; then fail "guard missed planted call: $call"; else ok "guard trips on: $call"; fi
done

dir="$TMP/guard-run"
copy_scripts "$dir"
printf '%s\n' 'd.getCollection("x").insertOne({});' >>"$dir/$NAME.inventory.js"
export FAKE_MODE=clean FAKE_LOG="$TMP/kubectl-guard.log"; : >"$FAKE_LOG"
set +e; PATH="$FAKEBIN:$PATH" bash "$dir/$NAME.sh" --context fake-ctx >/dev/null 2>&1; rc=$?; set -e
if [ "$rc" -eq 1 ] && [ ! -s "$FAKE_LOG" ]; then ok "refused script exits 1 before any kubectl call"; else fail "refused script: rc=$rc, kubectl log: $(cat "$FAKE_LOG")"; fi

# --- 2. output contract with a fake kubectl ------------------------------------------------------------------------
run_fake clean
header="$(printf 'tenant\tkind\tid\tdetail\tclass')"
if [ "$RC" -eq 0 ] && [ "$OUT" = "$header" ] && grep -q 'every tenant holds the complete seed' <<<"$ERR"; then
    ok "clean run: exit 0, TSV header only"
else fail "clean run: rc=$RC out=$OUT err=$ERR"; fi
if grep -q 'octosystem  *entities 41/41 missing=- unexpected=- associations 23/23 (missing 0, duplicate 0)' <<<"$ERR"; then
    ok "clean run prints the per-tenant summary"
else fail "summary missing: $ERR"; fi
if grep -q 'exec -i octo-mongodb-0 -c mongod' <<<"$LOG" && grep -q 'readPreference=secondaryPreferred&maxStalenessSeconds=90' <<<"$JS" \
    && ! grep -q 'PASSWORD-IN-ARGV' <<<"$LOG" && ! grep -q 'fake-pw-0815' "$TMP/out" "$TMP/err" && ! grep -q 'fake-pw-0815' <<<"$JS"; then
    ok "pod octo-mongodb-0; password only on stdin (not in argv, output or JavaScript); secondaryPreferred"
else fail "password handling or pod: $LOG"; fi
if grep -q '^const PARAMS = {"systemDb":"octosystem","tenants":\[\]};$' <<<"$JS"; then ok "default params: system DB octosystem, all tenants"; else fail "params: $(grep PARAMS <<<"$JS")"; fi

run_fake clean --system-db s6octosystem tenanta,tenantb tenantc
if grep -q '^const PARAMS = {"systemDb":"s6octosystem","tenants":\["tenanta","tenantb","tenantc"\]};$' <<<"$JS"; then
    ok "--system-db and tenant list reach the JavaScript"
else fail "params: $(grep PARAMS <<<"$JS")"; fi

printf 'fake-pw-0815\n' >"$TMP/pw"
run_fake clean --pod mongodb-0 --container mongodb --password-file "$TMP/pw"
if [ "$RC" -eq 0 ] && ! grep -q 'get secret' <<<"$LOG" && ! grep -q 'get pods' <<<"$LOG" && grep -q 'exec -i mongodb-0 -c mongodb' <<<"$LOG"; then
    ok "--password-file, --pod and --container: no secret or pod lookup"
else fail "password file: rc=$RC log=$LOG err=$ERR"; fi

run_fake clean 'bad"tenant'
if [ "$RC" -eq 1 ] && grep -q 'invalid tenant id' <<<"$ERR" && [ ! -s "$FAKE_LOG" ]; then
    ok "tenant id with a quote is refused before any kubectl call (no secret read)"
else fail "invalid tenant: rc=$RC err=$ERR kubectl log=$LOG"; fi
run_fake clean --system-db 'x");drop'
if [ "$RC" -eq 1 ] && grep -q 'invalid --system-db' <<<"$ERR" && [ ! -s "$FAKE_LOG" ]; then
    ok "--system-db with code is refused before any kubectl call"
else fail "invalid system db: rc=$RC err=$ERR kubectl log=$LOG"; fi

run_fake findings
if [ "$RC" -eq 2 ] && grep -q $'^tenanta\tentity\t660000000000000000000001\tSystem.Identity/Role\tMISSING$' <<<"$OUT"; then
    ok "findings: TSV row, exit 2"
else fail "findings: rc=$RC out=$OUT"; fi

run_fake nodb
if [ "$RC" -eq 1 ] && grep -q 'not found -- incomplete' <<<"$ERR"; then ok "tenant database not found: exit 1"; else fail "nodb: rc=$RC err=$ERR"; fi

run_fake incomplete
if [ "$RC" -eq 1 ] && grep -q 'incomplete' <<<"$ERR"; then ok "missing END marker: exit 1"; else fail "incomplete: rc=$RC err=$ERR"; fi

# --- 3. the JavaScript against the mock ----------------------------------------------------------------------------
if node "$HERE/$NAME.inventory.test.mjs" >"$TMP/node.out" 2>&1; then
    ok "inventory JavaScript against the MongoDB mock ($(tail -1 "$TMP/node.out"))"
else
    fail "inventory JavaScript against the MongoDB mock"; cat "$TMP/node.out"
fi

echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
