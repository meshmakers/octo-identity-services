#!/usr/bin/env bash
# identity-bootstrap-seed-check.sh -- READ-ONLY check of the System.Identity.Bootstrap seed in every tenant database.
#
# The identity service applies the System.Identity.Bootstrap blueprint to the system tenant and to every child tenant
# on startup, the child tenants in parallel. Before the fix of the shared import command, two tenant imports that ran
# at the same time shared one import state: one tenant could lose seed entities or associations, or another tenant's
# queued entities could be written in its session. This script lists, per tenant database:
#   * whether each seed entity of the blueprint exists in the tenant (present / MISSING),
#   * whether a seed rtId exists more than once (DUPLICATE) or with another ckTypeId (TYPE-MISMATCH),
#   * whether a seed client carries provisionedByParentTenantId of a tenant that is not one of its ancestors
#     (FOREIGN-PROVISIONING),
#   * whether each seed association exists (ASSOC-MISSING) exactly once (ASSOC-DUPLICATE).
# The expected entities and associations are embedded in identity-bootstrap-seed-check.inventory.js; a unit test
# (BootstrapSeedCheckManifestTests) keeps them equal to the seed files.
#
# Data source: the cluster's MongoDB, read directly (system DB tenant list, per tenant DB the seed entities and
# RtAssociation) with mongosh inside the MongoDB pod, readPreference=secondaryPreferred. No octo-cli, no token.
#
# It writes nothing: the JavaScript it runs uses read operations only, and a guard refuses to run when the file
# contains a write-capable call (--self-check runs the guard alone; scripts/tests/identity-bootstrap-seed-check.test.sh
# proves that it trips and runs the JavaScript against a read-only mock). It never loads secret material (every query
# projects _id, ckTypeId and provisionedByParentTenantId; client secrets are not read). The MongoDB password is read
# from the cluster secret (or from --password-file) into a shell variable and passed to mongosh on stdin -- never in
# argv, the environment or the output. The JavaScript also travels on stdin; the in-pod runner keeps it (no secret) in
# a private temporary file for the run and removes it afterwards.
#
# Access: kubectl access to the namespace of the MongoDB pods (get secret, list pods, exec) -- on shared clusters via
# breakglass or Semaphore (agent-operating-rules), never through extra RBAC rights.
# Requirements: bash >= 3.2, kubectl; in the MongoDB pod: sh, mktemp and mongosh.
# Exit codes: 0 = every tenant holds the complete seed, 2 = findings, 1 = error / incomplete.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INVENTORY_JS="$SCRIPT_DIR/identity-bootstrap-seed-check.inventory.js"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME --context <kube-context> [options] [tenant ...]
       $SCRIPT_NAME --self-check

Read-only check of the System.Identity.Bootstrap seed per tenant, read straight from the cluster's MongoDB.

  --context <ctx>         kube context of the cluster. Required.
  --kubeconfig <file>     kubeconfig to use (default: kubectl's default / \$KUBECONFIG).
  tenant ...              Tenants to check (space or comma separated). Default: the system tenant + every tenant in
                          <system-db>.RtEntity_SystemTenant.
  --system-db <name>      System database (default: octosystem; a local lane stack uses its own).
  --namespace <ns>        Namespace of MongoDB (default: mongodb).
  --pod <name>            MongoDB pod to exec into (default: first pod octo-mongodb-<n>).
  --container <name>      Container of the pod that has mongosh (default: mongod).
  --secret <name>         Secret holding the admin password (default: octo-mongodb-admin-octo-system-admin, key password).
  --password-file <file>  Read the password from the first line of this file instead of the secret (local stacks).
  --mongo-user <user>     MongoDB user (default: octo-system-admin). Read access to every database is enough.
  --self-check            Only run the write guard over the JavaScript and exit (0 = clean, 1 = refused).
  -h, --help              This help.

Output: TSV on stdout (tenant, kind, id, detail, class) for every finding; one summary line per tenant on stderr
(entities present/expected, missing and unexpected rtIds, associations present/expected, missing, duplicate).

Exit codes: 0 = clean, 2 = findings, 1 = error / incomplete.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$*" >&2; }

# Write guard: the JavaScript may only read. Refuses write-capable collection/database calls, server commands,
# $out/$merge stages, dynamic code (eval/Function/require/load), Reflect/Proxy/globalThis and the replica-set and
# sharding helpers (rs./sh.), and member access by string literal or by a computed key (obj["insertOne"], obj[k]),
# which would hide a call from the other patterns. Comments are scanned too -- keep them free of such calls. The guard
# is a deny list; a MongoDB user with read access only (--mongo-user, --secret) makes the read-only promise technical.
WRITE_PATTERNS=(
    '\.[[:space:]]*(insert|update|replace|delete|remove|save|drop|create|rename|bulkWrite|initializeOrderedBulkOp|initializeUnorderedBulkOp|findAndModify|findOneAnd|aggregate|mapReduce|watch|runCommand|adminCommand|grant|revoke|setProfilingLevel|fsync|shutdown|killOp|compact|reIndex|hideIndex|unhideIndex|convertToCapped|getCollectionWriteable|changeUserPassword|ensureIndex|reconfig|stepDown|setFeatureCompatibilityVersion)[A-Za-z]*[[:space:]]*\('
    '\$(out|merge)'
    '(^|[^A-Za-z0-9_$.])(eval|Function|require|load|runCommand|adminCommand)[[:space:]]*\('
    '(^|[^A-Za-z0-9_$])(Reflect|Proxy|globalThis|rs|sh)[[:space:]]*\.'
    '[]A-Za-z0-9_$)][[:space:]]*\[[[:space:]]*[A-Za-z_$]'
    '[]A-Za-z0-9_$)][[:space:]]*\[[[:space:]]*["'"'"'`]'
)
write_guard() {
    local p refused=0
    [ -f "$INVENTORY_JS" ] || { echo "refusing: $INVENTORY_JS is missing" >&2; return 1; }
    for p in "${WRITE_PATTERNS[@]}"; do
        if grep -n -E -e "$p" "$INVENTORY_JS" >&2; then
            echo "refusing: $(basename "$INVENTORY_JS") contains a write-capable call (pattern: $p)" >&2
            refused=1
        fi
    done
    return "$refused"
}

CONTEXT=""
KUBECONFIG_FILE=""
NAMESPACE="mongodb"
POD=""
CONTAINER="mongod"
SECRET="octo-mongodb-admin-octo-system-admin"
PASSWORD_FILE=""
MONGO_USER="octo-system-admin"
SYSTEM_DB="octosystem"
SELF_CHECK=false
TENANTS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --context) [ $# -ge 2 ] || die "--context needs a value"; CONTEXT="$2"; shift 2 ;;
        --kubeconfig) [ $# -ge 2 ] || die "--kubeconfig needs a value"; KUBECONFIG_FILE="$2"; shift 2 ;;
        --namespace) [ $# -ge 2 ] || die "--namespace needs a value"; NAMESPACE="$2"; shift 2 ;;
        --pod) [ $# -ge 2 ] || die "--pod needs a value"; POD="$2"; shift 2 ;;
        --container) [ $# -ge 2 ] || die "--container needs a value"; CONTAINER="$2"; shift 2 ;;
        --secret) [ $# -ge 2 ] || die "--secret needs a value"; SECRET="$2"; shift 2 ;;
        --password-file) [ $# -ge 2 ] || die "--password-file needs a value"; PASSWORD_FILE="$2"; shift 2 ;;
        --mongo-user) [ $# -ge 2 ] || die "--mongo-user needs a value"; MONGO_USER="$2"; shift 2 ;;
        --system-db) [ $# -ge 2 ] || die "--system-db needs a value"; SYSTEM_DB="$2"; shift 2 ;;
        --self-check) SELF_CHECK=true; shift ;;
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
# Everything that can be refused is refused before the first kubectl call (no secret is read for a run that cannot run).
# Names go into the JavaScript as string literals: allow only the characters tenant ids, database and user names use.
NAME_RE='^[A-Za-z0-9_.-]+$'
[[ "$SYSTEM_DB" =~ $NAME_RE ]] || die "invalid --system-db"
[[ "$MONGO_USER" =~ $NAME_RE ]] || die "invalid --mongo-user"
TENANTS_JSON=""
for t in ${TENANTS[@]+"${TENANTS[@]}"}; do
    [[ "$t" =~ $NAME_RE ]] || die "invalid tenant id: $t"
    TENANTS_JSON="${TENANTS_JSON:+$TENANTS_JSON,}\"$t\""
done
PARAMS_JS="const PARAMS = {\"systemDb\":\"$SYSTEM_DB\",\"tenants\":[$TENANTS_JSON]};"
command -v kubectl >/dev/null || die "kubectl is required"
write_guard || die "write guard refused the JavaScript -- not running anything"

KUBECTL=(kubectl --context "$CONTEXT" -n "$NAMESPACE")
[ -n "$KUBECONFIG_FILE" ] && KUBECTL=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" -n "$NAMESPACE")

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bootstrap-seed-check.XXXXXX")"
MONGO_PW=""
trap 'MONGO_PW=""; rm -rf "$WORK"' EXIT

if [ -z "$POD" ]; then
    POD="$("${KUBECTL[@]}" get pods -o name 2>"$WORK/kubectl.err" | sed -n 's#^pod/\(octo-mongodb-[0-9][0-9]*\)$#\1#p' | head -1 || true)"
    [ -n "$POD" ] || { sed -n '1,3p' "$WORK/kubectl.err" >&2; die "no octo-mongodb-<n> pod in namespace $NAMESPACE (context $CONTEXT)"; }
fi
# The password stays in this variable; it is only ever written to kubectl's stdin.
if [ -n "$PASSWORD_FILE" ]; then
    [ -r "$PASSWORD_FILE" ] || die "cannot read --password-file"
    IFS= read -r MONGO_PW <"$PASSWORD_FILE" || true
    MONGO_PW="${MONGO_PW%$'\r'}"
    [ -n "$MONGO_PW" ] || die "--password-file is empty"
else
    MONGO_PW="$("${KUBECTL[@]}" get secret "$SECRET" -o jsonpath='{.data.password}' 2>"$WORK/kubectl.err" | base64 -d 2>/dev/null || true)"
    [ -n "$MONGO_PW" ] || { sed -n '1,3p' "$WORK/kubectl.err" >&2; die "cannot read the password from secret $NAMESPACE/$SECRET"; }
fi

# Opens the connection with the password from stdin (first line). Not part of the guarded file: it reads stdin only.
# The pod's own mongod is only the seed: hello() names the replica set and its members, and the check connects to the
# replica set, so readPreference=secondaryPreferred is honoured and a member lagging more than maxStalenessSeconds is
# never read. A standalone server is used directly.
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
PRELUDE_JS="${PRELUDE_JS//__MONGO_USER__/\"$MONGO_USER\"}"

# Only this short runner crosses the exec request: it reads the password (first stdin line) into a shell variable,
# writes the rest of stdin (the JavaScript, no secret) to a private temporary file in the pod, runs it with mongosh
# (password on mongosh's stdin via the printf builtin, never in argv) and removes the file.
read -r -d '' REMOTE_SH <<'SH' || true
umask 077; d="$(mktemp -d)" || exit 1; trap 'rm -rf "$d"' EXIT; IFS= read -r pw; cat >"$d/run.js"
printf '%s\n' "$pw" | mongosh --quiet --nodb "$d/run.js"
SH

info "Reading MongoDB in $CONTEXT ($NAMESPACE/$POD), system DB $SYSTEM_DB, read-only ..."
if ! { printf '%s\n' "$MONGO_PW"; printf '%s\n%s\n' "$PRELUDE_JS" "$PARAMS_JS"; cat "$INVENTORY_JS"; } \
    | "${KUBECTL[@]}" exec -i "$POD" -c "$CONTAINER" -- sh -c "$REMOTE_SH" >"$WORK/check.out" 2>"$WORK/check.err"; then
    # mongosh errors do not contain the password; strip any credentials from URIs anyway.
    sed -E 's#//[^/@[:space:]]*@#//***@#g' "$WORK/check.err" | grep -v -E 'EACCES|history' | tail -3 >&2 || true
    MONGO_PW=""
    die "check failed"
fi
MONGO_PW=""

grep -q '^END$' "$WORK/check.out" || die "check output incomplete (no END marker)"
info "# connection: $(sed -n 's/^CONN //p' "$WORK/check.out" | head -1), readPreference=secondaryPreferred"
info "# seed: $(sed -n 's/^SEED	//p' "$WORK/check.out" | awk -F'\t' '{ printf "%s, %s entities, %s associations", $1, $2, $3 }')"
sed -n 's/^ROW	//p' "$WORK/check.out" >"$WORK/rows.tsv"
sed -n 's/^SUM	//p' "$WORK/check.out" >"$WORK/sums.tsv"

printf 'tenant\tkind\tid\tdetail\tclass\n'
cat "$WORK/rows.tsv"

{
    echo
    echo "# per tenant: entities present/expected, missing and unexpected rtIds, associations present/expected"
    awk -F'\t' '{ printf "# %-28s entities %s/%s missing=%s unexpected=%s associations %s/%s (missing %s, duplicate %s)\n",
        $1, $2, $3, $4, $5, $6, $7, $8, $9 }' "$WORK/sums.tsv"
} >&2

ERRORS="$(awk -F'\t' '$5 == "NO-DATABASE"' "$WORK/rows.tsv" | wc -l | tr -d ' ')"
FINDINGS="$(awk -F'\t' '$5 != "NO-DATABASE"' "$WORK/rows.tsv" | wc -l | tr -d ' ')"
if [ "$ERRORS" -gt 0 ]; then info "Result: $ERRORS tenant database(s) not found -- incomplete (exit 1)"; exit 1; fi
if [ "$FINDINGS" -gt 0 ]; then info "Result: $FINDINGS finding(s) (exit 2)"; exit 2; fi
info "Result: every tenant holds the complete seed (exit 0)"
exit 0
