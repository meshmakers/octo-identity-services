#!/usr/bin/env bash
# Tests for scripts/identity-secret-management-role-check.sh (AB#8155). No cluster needed.
#   1. the write guard passes the shipped JavaScript and refuses each planted write-capable call -- and then never
#      reaches kubectl;
#   2. with a fake kubectl: output contract (TSV, exit codes 0/2/1), before/after snapshot comparison, and the MongoDB
#      password reaching mongosh on stdin only (never in an argument, never in the output);
#   3. the inventory/snapshot JavaScript against an in-memory MongoDB mock (node, *.inventory.test.mjs).
# Run: bash scripts/tests/identity-secret-management-role-check.test.sh   (needs bash, jq, node)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
NAME="identity-secret-management-role-check"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/secret-role-check-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
PASSED=0
ok() { PASSED=$((PASSED + 1)); echo "ok - $*"; }
fail() { FAILED=$((FAILED + 1)); echo "not ok - $*"; }

# copy_scripts <dir>: a private copy of the script and its JavaScript, so tests can plant calls.
copy_scripts() {
    mkdir -p "$1"
    cp "$SRC/$NAME.sh" "$SRC/$NAME.inventory.js" "$SRC/$NAME.snapshot.js" "$1/"
}

# Fake kubectl: get pods / get secret / exec. exec checks that the password arrives on stdin and in no argument, then
# prints canned mongosh output chosen by FAKE_MODE (clean | findings | error | changed | incomplete).
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
        IFS= read -r line
        [ "$line" = "$PW" ] || { echo "password not on stdin" >&2; exit 8; }
        eval_arg="${*: -1}"
        case "$eval_arg" in
            *'print("SNAP '*)
                n=$(( $(cat "$FAKE_LOG.snaps" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$FAKE_LOG.snaps"
                xt=1; [ "$FAKE_MODE" = changed ] && [ "$n" -eq 2 ] && xt=2
                echo "SNAP {\"octosystem\":{\"users\":3,\"xtUsers\":0,\"mappings\":0,\"newestUser\":\"a\",\"newestMapping\":\"\"},\"tenanta\":{\"users\":5,\"xtUsers\":$xt,\"mappings\":2,\"newestUser\":\"b\",\"newestMapping\":\"c\"}}" ;;
            *)
                printf 'ROW\toctosystem\tuser\tu0\troot\tyes\tno\tHOLDS\n'
                printf 'ROW\ttenanta\tuser\tu1\tadm***@example.com\tyes\tno\tHOLDS\n'
                case "$FAKE_MODE" in
                    findings) printf 'ROW\ttenanta\tuser\tu3\tbob\tno\tyes\tLOSES\nROW\ttenantb\ttenant\t-\t-\t-\t-\tNO-ROLE\n' ;;
                    error) printf 'ROW\tnope\ttenant\t-\t-\t-\t-\tERROR\n' ;;
                esac
                [ "$FAKE_MODE" = incomplete ] || echo "END" ;;
        esac ;;
    *) echo "unexpected kubectl call" >&2; exit 7 ;;
esac
FAKE
chmod +x "$FAKEBIN/kubectl"

# run_fake <mode> <args...>: runs the real script against the fake kubectl; sets RC, OUT, ERR, LOG.
run_fake() {
    local mode="$1"; shift
    export FAKE_MODE="$mode" FAKE_LOG="$TMP/kubectl-$mode.log"
    rm -f "$FAKE_LOG" "$FAKE_LOG.snaps"; touch "$FAKE_LOG"
    set +e
    PATH="$FAKEBIN:$PATH" bash "$SRC/$NAME.sh" --context fake-ctx "$@" >"$TMP/out" 2>"$TMP/err"
    RC=$?
    set -e
    OUT="$(cat "$TMP/out")"; ERR="$(cat "$TMP/err")"; LOG="$(cat "$FAKE_LOG")"
}

# --- 1. write guard ------------------------------------------------------------------------------------------------
if bash "$SRC/$NAME.sh" --self-check 2>/dev/null; then ok "guard passes the shipped JavaScript"; else fail "guard refuses the shipped JavaScript"; fi

PLANTED=(
    'd.getCollection("RtEntity_SystemIdentityUser").insertOne({});'
    'd.getCollection("x").insertMany([]);'
    'd.getCollection("x").updateOne({}, {});'
    'd.getCollection("x").updateMany({}, {});'
    'd.getCollection("x").replaceOne({}, {});'
    'd.getCollection("x").deleteOne({});'
    'd.getCollection("x").deleteMany({});'
    'd.getCollection("x").remove({});'
    'd.getCollection("x").save({});'
    'd.getCollection("x").drop();'
    'd.dropDatabase();'
    'd.createCollection("x");'
    'd.getCollection("x").createIndex({ a: 1 });'
    'd.getCollection("x").renameCollection("y");'
    'd.getCollection("x").bulkWrite([]);'
    'd.getCollection("x").initializeUnorderedBulkOp();'
    'd.getCollection("x").findAndModify({});'
    'd.getCollection("x").findOneAndUpdate({}, {});'
    'd.getCollection("x").findOneAndDelete({});'
    'd.getCollection("x").aggregate([{ $out: "y" }]);'
    'const stage = { $merge: { into: "y" } };'
    'd.runCommand({ insert: "x", documents: [{}] });'
    'conn.adminCommand({ dropDatabase: 1 });'
    'runCommand({ delete: "x" });'
    'd.getCollection("x")["insertOne"]({});'
    'd.getCollection("x") . insertOne ({});'
    'eval("d.getCollection(1)");'
    'new Function("return 1")();'
    'require("fs");'
)
i=0
for call in "${PLANTED[@]}"; do
    for target in inventory snapshot; do
        i=$((i + 1))
        dir="$TMP/guard-$i"
        copy_scripts "$dir"
        printf '%s\n' "$call" >>"$dir/$NAME.$target.js"
        if bash "$dir/$NAME.sh" --self-check >/dev/null 2>&1; then
            fail "guard missed planted call in $target.js: $call"
        else
            ok "guard trips on $target.js: $call"
        fi
    done
done

# A refused script must not touch the cluster at all.
dir="$TMP/guard-run"
copy_scripts "$dir"
printf '%s\n' 'd.getCollection("x").insertOne({});' >>"$dir/$NAME.inventory.js"
export FAKE_MODE=clean FAKE_LOG="$TMP/kubectl-guard.log"; : >"$FAKE_LOG"
set +e; PATH="$FAKEBIN:$PATH" bash "$dir/$NAME.sh" --context fake-ctx >/dev/null 2>&1; rc=$?; set -e
if [ "$rc" -eq 1 ] && [ ! -s "$FAKE_LOG" ]; then ok "refused script exits 1 before any kubectl call"; else fail "refused script: rc=$rc, kubectl log: $(cat "$FAKE_LOG")"; fi

# --- 2. output contract with a fake kubectl ------------------------------------------------------------------------
run_fake clean
header="$(printf 'tenant\tkind\tid\tname\tsecret_management\ttoday_tm_or_um\tclass')"
if [ "$RC" -eq 0 ] && [ "$(printf '%s\n' "$OUT" | head -1)" = "$header" ] && [ "$(printf '%s\n' "$OUT" | wc -l | tr -d ' ')" -eq 3 ]; then
    ok "clean run: exit 0, TSV header + rows"
else fail "clean run: rc=$RC out=$OUT err=$ERR"; fi
case "$ERR" in *"snapshot before == after: equal"*) ok "clean run reports equal snapshots" ;; *) fail "no snapshot line: $ERR" ;; esac
case "$ERR" in *"dbs=2 users=8 xt_users=1 mappings=2"*) ok "clean run prints snapshot counts" ;; *) fail "snapshot counts missing: $ERR" ;; esac
if [ "$(grep -c ' exec ' <<<"$LOG")" -eq 3 ] && grep -q 'exec -i octo-mongodb-0 -c mongod' <<<"$LOG"; then
    ok "three mongosh runs (snapshot, inventory, snapshot) in pod octo-mongodb-0"
else fail "unexpected kubectl calls: $LOG"; fi
if grep -q 'readPreference=secondaryPreferred&maxStalenessSeconds=90' <<<"$LOG" && grep -q 'replicaSet=' <<<"$LOG" && ! grep -q 'PASSWORD-IN-ARGV' <<<"$LOG" \
    && ! grep -q 'fake-pw-0815' "$TMP/out" "$TMP/err"; then
    ok "password only on stdin (not in argv or output); replica-set connection with secondaryPreferred"
else fail "password handling: $LOG"; fi

run_fake findings
if [ "$RC" -eq 2 ] && grep -q $'\tLOSES$' <<<"$OUT" && grep -q 'ROLE-MISSING' <<<"$ERR"; then ok "findings: exit 2"; else fail "findings: rc=$RC err=$ERR"; fi

run_fake error
if [ "$RC" -eq 1 ] && grep -q $'^nope\ttenant\t-\t-\t-\t-\tERROR$' <<<"$OUT"; then ok "unknown tenant: ERROR row, exit 1"; else fail "error: rc=$RC out=$OUT"; fi

run_fake changed
if [ "$RC" -eq 1 ] && grep -q 'snapshot before != after' <<<"$ERR" && grep -q 'tenanta' <<<"$ERR"; then
    ok "snapshot changed: exit 1, names the changed database"
else fail "changed: rc=$RC err=$ERR"; fi

run_fake incomplete
if [ "$RC" -eq 1 ] && grep -q 'incomplete' <<<"$ERR"; then ok "missing END marker: exit 1"; else fail "incomplete: rc=$RC err=$ERR"; fi

run_fake clean tenanta,octosystem --ids-only
if grep -q '"tenants":\["tenanta","octosystem"\]' <<<"$LOG" && grep -q '"idsOnly":true' <<<"$LOG"; then
    ok "tenant filter and --ids-only reach the JavaScript"
else fail "params: $LOG"; fi

set +e; bash "$SRC/$NAME.sh" --context x --discover all >/dev/null 2>"$TMP/err"; rc=$?; set -e
if [ "$rc" -eq 1 ] && grep -q 'removed with AB#8155' "$TMP/err"; then ok "--discover is rejected with a hint"; else fail "--discover: rc=$rc"; fi

# --- 3. JavaScript against the MongoDB mock ------------------------------------------------------------------------
if node "$HERE/$NAME.inventory.test.mjs"; then ok "inventory/snapshot JavaScript tests"; else fail "inventory/snapshot JavaScript tests"; fi

echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
