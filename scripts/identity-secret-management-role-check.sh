#!/usr/bin/env bash
# identity-secret-management-role-check.sh -- READ-ONLY role inventory for AB#5861 (read-only since AB#8155).
#
# Since AB#5861 the API secret writes of the identity service (create/rotate/delete secrets of clients and
# API resources, a clientSecret in client create/update, the Client.AddSecret/RemoveSecret methods) need the
# tenant role SecretManagement. While IdentityApiAuthorization:SecretManagementRoleEnforcement=Warn (the shipped
# default) TenantManagement/UserManagement still pass; with Enforce only SecretManagement does.
#
# This script lists, per tenant:
#   * whether the SecretManagement role exists (System.Identity.Bootstrap >= 1.7.0, rtId 660000000000000000000060),
#   * every subject (user, client, external tenant user mapping) that holds it, direct or via a group,
#   * every subject that may write API secrets today (TenantManagement or UserManagement, direct or via a
#     group) but does NOT hold SecretManagement -- these lose the secret writes once the switch is Enforce.
#
# Data source: the cluster's MongoDB, read directly (system DB tenant list; per tenant DB the identity roles, groups,
# users, clients, external tenant user mappings and the AssignedRole/GroupMember/ChildGroup associations) with
# mongosh inside the MongoDB pod, readPreference=secondaryPreferred. It uses NO octo-cli and NO token exchange: the
# earlier octo-cli version ran "GraphQl -tid" per tenant, and that exchange created an xt_ shadow user for the caller in
# every tenant it did not have one yet (AB#8155).
#
# It writes nothing:
#   * the JavaScript it runs (identity-secret-management-role-check.{snapshot,inventory}.js next to this script) uses
#     read operations only; a guard refuses to run when either file contains a write-capable call (--self-check runs
#     the guard alone; scripts/tests/identity-secret-management-role-check.test.sh proves it trips);
#   * an identity snapshot (per tenant DB: users, xt_ users, external tenant user mappings, newest change of users and
#     mappings) is taken before and after the inventory; if they differ the script says so and exits 1.
# It never loads secret material (every query projects the attributes it needs; password hashes, security stamps,
# client secrets and tokens are not read) and masks e-mail addresses unless --with-email. The MongoDB password is read
# from the cluster secret into a shell variable and passed to mongosh on stdin -- never in argv, the environment or
# the output. The JavaScript also travels on stdin (AB#8431): the exec request carries only a short runner, so the
# script works through the Rancher proxy; the runner keeps the JavaScript (no secret) in a private temporary file in
# the pod for the run and removes it afterwards.
#
# Access: kubectl access to the namespace of the MongoDB pods (get secret, list pods, exec) -- on shared clusters via
# breakglass or Semaphore (agent-operating-rules), never through extra RBAC rights.
# Requirements: bash >= 3.2, kubectl, jq; in the MongoDB pod: sh, mktemp and mongosh.
# Exit codes: 0 = every tenant has the role and nobody loses access, 2 = findings, 1 = error / incomplete /
# snapshot changed.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNAPSHOT_JS="$SCRIPT_DIR/identity-secret-management-role-check.snapshot.js"
INVENTORY_JS="$SCRIPT_DIR/identity-secret-management-role-check.inventory.js"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME --context <kube-context> [options] [tenant ...]
       $SCRIPT_NAME --self-check

Read-only SecretManagement inventory for the AB#5861 rollout, read straight from the cluster's MongoDB.
No octo-cli, no token exchange; writes nothing (guarded, verified by a before/after identity snapshot).

  --context <ctx>       kube context of the cluster (e.g. the breakglass context of test-2). Required.
  --kubeconfig <file>   kubeconfig to use (default: kubectl's default / \$KUBECONFIG).
  tenant ...            Tenants to check (space or comma separated). Default: octosystem + every tenant in
                        octosystem.RtEntity_SystemTenant.
  --namespace <ns>      Namespace of MongoDB (default: mongodb).
  --pod <name>          MongoDB pod to exec into (default: first pod octo-mongodb-<n>).
  --secret <name>       Secret holding the admin password (default: octo-mongodb-admin-octo-system-admin, key password).
  --mongo-user <user>   MongoDB admin user (default: octo-system-admin).
  --with-email          Show user names that are e-mail addresses unmasked.
  --ids-only            Print rtIds only, no names (for work items and reports).
  --self-check          Only run the write guard over the JavaScript files and exit (0 = clean, 1 = refused).
  -h, --help            This help.

Access: kubectl get secret / list pods / exec in the MongoDB namespace -- via breakglass or Semaphore on shared clusters.

Output: TSV on stdout (tenant, kind, id, name, secret_management, today, class), summary on stderr.
  class HOLDS  = holds SecretManagement (direct or via group)
  class LOSES  = holds TenantManagement/UserManagement but not SecretManagement -> denied under Enforce
  tenant rows with class NO-ROLE / ERROR = role missing (bootstrap < 1.7.0) / tenant database not found

Exit codes: 0 = clean, 2 = findings (LOSES or NO-ROLE rows), 1 = error / incomplete / snapshot before != after.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$*" >&2; }

# Write guard: the JavaScript may only read. Refuses write-capable collection/database calls, server commands,
# $out/$merge stages, dynamic code (eval/Function/require/load) and member access by string literal (obj["insertOne"]),
# which would hide a call from the other patterns. Comments are scanned too -- keep them free of such calls.
WRITE_PATTERNS=(
    '\.[[:space:]]*(insert|update|replace|delete|remove|save|drop|create|rename|bulkWrite|initializeOrderedBulkOp|initializeUnorderedBulkOp|findAndModify|findOneAnd|aggregate|mapReduce|watch|runCommand|adminCommand|grant|revoke|setProfilingLevel|fsync|shutdown|killOp|compact|reIndex|hideIndex|unhideIndex|convertToCapped|getCollectionWriteable)[A-Za-z]*[[:space:]]*\('
    '\$(out|merge)'
    '(^|[^A-Za-z0-9_$.])(eval|Function|require|load|runCommand|adminCommand)[[:space:]]*\('
    '[]A-Za-z0-9_$)][[:space:]]*\[[[:space:]]*["'"'"'`]'
)
write_guard() {
    local f p refused=0
    for f in "$SNAPSHOT_JS" "$INVENTORY_JS"; do
        [ -f "$f" ] || { echo "refusing: $f is missing" >&2; refused=1; continue; }
        for p in "${WRITE_PATTERNS[@]}"; do
            if grep -n -E -e "$p" "$f" >&2; then
                echo "refusing: $(basename "$f") contains a write-capable call (pattern: $p)" >&2
                refused=1
            fi
        done
    done
    return "$refused"
}

CONTEXT=""
KUBECONFIG_FILE=""
NAMESPACE="mongodb"
POD=""
SECRET="octo-mongodb-admin-octo-system-admin"
MONGO_USER="octo-system-admin"
WITH_EMAIL=false
IDS_ONLY=false
SELF_CHECK=false
TENANTS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --context) [ $# -ge 2 ] || die "--context needs a value"; CONTEXT="$2"; shift 2 ;;
        --kubeconfig) [ $# -ge 2 ] || die "--kubeconfig needs a value"; KUBECONFIG_FILE="$2"; shift 2 ;;
        --namespace) [ $# -ge 2 ] || die "--namespace needs a value"; NAMESPACE="$2"; shift 2 ;;
        --pod) [ $# -ge 2 ] || die "--pod needs a value"; POD="$2"; shift 2 ;;
        --secret) [ $# -ge 2 ] || die "--secret needs a value"; SECRET="$2"; shift 2 ;;
        --mongo-user) [ $# -ge 2 ] || die "--mongo-user needs a value"; MONGO_USER="$2"; shift 2 ;;
        --with-email) WITH_EMAIL=true; shift ;;
        --ids-only) IDS_ONLY=true; shift ;;
        --self-check) SELF_CHECK=true; shift ;;
        --discover) die "--discover was removed with AB#8155: the script reads every tenant from MongoDB; pass tenants to narrow it" ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option $1" ;;
        *) IFS=',' read -r -a _parts <<<"$1"; for p in "${_parts[@]}"; do [ -n "$p" ] && TENANTS+=("$p"); done; shift ;;
    esac
done

if [ "$SELF_CHECK" = true ]; then
    write_guard || die "write guard refused the JavaScript"
    info "write guard: clean"
    exit 0
fi
[ -n "$CONTEXT" ] || { usage >&2; die "--context is required"; }
command -v kubectl >/dev/null || die "kubectl is required"
command -v jq >/dev/null || die "jq is required"
write_guard || die "write guard refused the JavaScript -- not running anything"

KUBECTL=(kubectl --context "$CONTEXT" -n "$NAMESPACE")
[ -n "$KUBECONFIG_FILE" ] && KUBECTL=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" -n "$NAMESPACE")

WORK="$(mktemp -d "${TMPDIR:-/tmp}/secret-role-check.XXXXXX")"
MONGO_PW=""
trap 'MONGO_PW=""; rm -rf "$WORK"' EXIT

if [ -z "$POD" ]; then
    POD="$("${KUBECTL[@]}" get pods -o name 2>"$WORK/kubectl.err" | sed -n 's#^pod/\(octo-mongodb-[0-9][0-9]*\)$#\1#p' | head -1 || true)"
    [ -n "$POD" ] || { sed -n '1,3p' "$WORK/kubectl.err" >&2; die "no octo-mongodb-<n> pod in namespace $NAMESPACE (context $CONTEXT)"; }
fi
# The password stays in this variable; it is only ever written to kubectl's stdin.
MONGO_PW="$("${KUBECTL[@]}" get secret "$SECRET" -o jsonpath='{.data.password}' 2>"$WORK/kubectl.err" | base64 -d 2>/dev/null || true)"
[ -n "$MONGO_PW" ] || { sed -n '1,3p' "$WORK/kubectl.err" >&2; die "cannot read the password from secret $NAMESPACE/$SECRET"; }

TENANTS_JSON="$(jq -cn '$ARGS.positional' --args ${TENANTS[@]+"${TENANTS[@]}"})"
PARAMS_JS="const PARAMS = $(jq -cn --argjson tenants "$TENANTS_JSON" --argjson withEmail "$WITH_EMAIL" --argjson idsOnly "$IDS_ONLY" \
    '{tenants: $tenants, withEmail: $withEmail, idsOnly: $idsOnly}');"
# Opens the connection with the password from stdin (first line). Not part of the guarded files: it reads stdin only.
# The pod's own mongod is only the seed: hello() names the replica set and its members, and the inventory connects to
# the replica set, so readPreference=secondaryPreferred is honoured (a direct connection would read whatever member the
# pod runs) and a member lagging more than maxStalenessSeconds is never read. A standalone server is used directly.
read -r -d '' PRELUDE_JS <<'JS' || true
const mongoAuth = "mongodb://" + encodeURIComponent(__MONGO_USER__) + ":" +
    encodeURIComponent(require("fs").readFileSync(0, "utf8").split("\n")[0]) + "@";
const seedConn = connect(mongoAuth + "localhost:27017/admin?authSource=admin&directConnection=true&readPreference=secondaryPreferred");
const seedHello = seedConn.hello();
const conn = seedHello.setName
    ? connect(mongoAuth + seedHello.hosts.join(",") + "/admin?authSource=admin&replicaSet=" + encodeURIComponent(seedHello.setName) +
        "&readPreference=secondaryPreferred&maxStalenessSeconds=90")
    : seedConn;
print("CONN " + (seedHello.setName ? "replicaSet=" + seedHello.setName + " members=" + seedHello.hosts.length : "standalone"));
JS
PRELUDE_JS="${PRELUDE_JS//__MONGO_USER__/$(jq -cn --arg u "$MONGO_USER" '$u')}"

# AB#8431: the JavaScript travels on stdin, not in the exec command. "mongosh --eval <script>" put the whole script into
# the exec request URL; through the Rancher proxy the 5.5 KB inventory came back as an nginx error page. Only this short
# runner crosses the URL: it reads the password (first stdin line) into a shell variable, writes the rest of stdin (the
# JavaScript, no secret) to a private temporary file in the pod, runs it with mongosh (password on mongosh's stdin via
# the printf builtin, never in argv) and removes the file. mongosh needs a file to run a script with its shell API.
read -r -d '' REMOTE_SH <<'SH' || true
umask 077; d="$(mktemp -d)" || exit 1; trap 'rm -rf "$d"' EXIT; IFS= read -r pw; cat >"$d/run.js"
printf '%s\n' "$pw" | mongosh --quiet --nodb "$d/run.js"
SH

# run_js <name> <js-file>: runs prelude + params + file in mongosh inside the pod; stdout -> $WORK/<name>.out.
run_js() {
    local name="$1" file="$2"
    if ! { printf '%s\n' "$MONGO_PW"; printf '%s\n%s\n' "$PRELUDE_JS" "$PARAMS_JS"; cat "$file"; } \
        | "${KUBECTL[@]}" exec -i "$POD" -c mongod -- sh -c "$REMOTE_SH" >"$WORK/$name.out" 2>"$WORK/$name.err"; then
        # mongosh errors do not contain the password; strip any credentials from URIs anyway.
        sed -E 's#//[^/@[:space:]]*@#//***@#g' "$WORK/$name.err" | grep -v -E 'EACCES|history' | tail -3 >&2 || true
        return 1
    fi
}

info "Reading MongoDB in $CONTEXT ($NAMESPACE/$POD), read-only ..."
run_js snap_before "$SNAPSHOT_JS" || die "snapshot before the inventory failed"
info "# connection: $(sed -n 's/^CONN //p' "$WORK/snap_before.out" | head -1), readPreference=secondaryPreferred"
run_js inventory "$INVENTORY_JS" || die "inventory failed"
run_js snap_after "$SNAPSHOT_JS" || die "snapshot after the inventory failed"
MONGO_PW=""

SNAP_BEFORE="$(sed -n 's/^SNAP //p' "$WORK/snap_before.out")"
SNAP_AFTER="$(sed -n 's/^SNAP //p' "$WORK/snap_after.out")"
[ -n "$SNAP_BEFORE" ] && [ -n "$SNAP_AFTER" ] || die "snapshot output missing"
grep -q '^END$' "$WORK/inventory.out" || die "inventory output incomplete (no END marker)"
sed -n 's/^ROW	//p' "$WORK/inventory.out" >"$WORK/rows.tsv"

printf 'tenant\tkind\tid\tname\tsecret_management\ttoday_tm_or_um\tclass\n'
cat "$WORK/rows.tsv"

{
    echo
    echo "# summary per tenant: holders of SecretManagement / subjects that lose API secret writes under Enforce"
    awk -F'\t' '{ t[$1] = 1; c[$1 SUBSEP $7]++ }
        END { for (k in t) printf "# %-28s holds=%d loses=%d%s%s\n", k, c[k SUBSEP "HOLDS"], c[k SUBSEP "LOSES"],
                (c[k SUBSEP "NO-ROLE"] ? " ROLE-MISSING" : ""), (c[k SUBSEP "ERROR"] ? " NO-DATABASE" : "") }' "$WORK/rows.tsv" | sort
    echo "# identity snapshot (all tenant DBs): $(jq -r '[.[] | objects] | "dbs=\(length) users=\(map(.users) | add // 0) xt_users=\(map(.xtUsers) | add // 0) mappings=\(map(.mappings) | add // 0)"' <<<"$SNAP_BEFORE")"
} >&2

if [ "$SNAP_BEFORE" != "$SNAP_AFTER" ]; then
    info "# snapshot before != after -- identities changed while the inventory ran. Changed databases (counts only):"
    jq -rn --argjson a "$SNAP_BEFORE" --argjson b "$SNAP_AFTER" \
        '($a | keys) + ($b | keys) | unique[] | select($a[.] != $b[.]) | . as $db
         | "#   \($db): before \($a[$db] | if type == "object" then {users, xtUsers, mappings} else . end | tojson) after \($b[$db] | if type == "object" then {users, xtUsers, mappings} else . end | tojson)"' >&2
    info "Result: snapshot changed (exit 1) -- re-run; if it persists, find who writes identities"
    exit 1
fi
info "# snapshot before == after: equal"

ERRORS="$(awk -F'\t' '$7 == "ERROR"' "$WORK/rows.tsv" | wc -l | tr -d ' ')"
FINDINGS="$(awk -F'\t' '$7 == "LOSES" || $7 == "NO-ROLE"' "$WORK/rows.tsv" | wc -l | tr -d ' ')"
if [ "$ERRORS" -gt 0 ]; then info "Result: $ERRORS tenant(s) not readable -- incomplete (exit 1)"; exit 1; fi
if [ "$FINDINGS" -gt 0 ]; then info "Result: $FINDINGS finding(s) (exit 2)"; exit 2; fi
info "Result: no findings (exit 0)"
exit 0
