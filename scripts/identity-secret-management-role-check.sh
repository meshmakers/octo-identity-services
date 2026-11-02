#!/usr/bin/env bash
# identity-secret-management-role-check.sh -- READ-ONLY role inventory for AB#5861.
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
# It only runs octo-cli READ commands (AuthStatus, GetTenants, GraphQl queries). One context is enough:
# octo-cli GraphQl -tid exchanges the token per tenant. It never writes, never reads secret values
# (clientSecrets is not queried) and masks e-mail addresses unless --with-email.
#
# Requirements: bash >= 3.2, octo-cli, jq.
# Exit codes: 0 = every tenant has the role and nobody loses access, 2 = findings, 1 = error / incomplete.

set -euo pipefail

OCTO_CLI="${OCTO_CLI:-octo-cli}"
SCRIPT_NAME="$(basename "$0")"
SECRET_ROLE_ID="660000000000000000000060"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME --context <ctx> [--discover children|recursive|all] [--with-email|--ids-only] [tenant ...]

Read-only SecretManagement inventory for the AB#5861 rollout.

  --context <ctx>     octo-cli context of the installation (e.g. test-2_octosystem). Its tenant is checked too.
  tenant ...          Tenants to check (space or comma separated). Default: discovered with GetTenants.
  --discover <mode>   children | recursive | all (default: all; 'all' needs the system tenant context).
  --with-email        Show user names that are e-mail addresses unmasked.
  --ids-only          Print rtIds only, no names (for work items and reports).
  -h, --help          This help.

Output: TSV on stdout (tenant, kind, id, name, secret_management, today, class), summary on stderr.
  class HOLDS  = holds SecretManagement (direct or via group)
  class LOSES  = holds TenantManagement/UserManagement but not SecretManagement -> denied under Enforce
  tenant rows with class NO-ROLE / ERROR = role missing (bootstrap < 1.7.0) / tenant not readable

Exit codes: 0 = clean, 2 = findings (LOSES or NO-ROLE rows), 1 = error / incomplete.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$*" >&2; }

CONTEXT=""
DISCOVER="all"
WITH_EMAIL=false
IDS_ONLY=false
TENANTS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --context) [ $# -ge 2 ] || die "--context needs a value"; CONTEXT="$2"; shift 2 ;;
        --discover) [ $# -ge 2 ] || die "--discover needs a value"; DISCOVER="$2"; shift 2 ;;
        --with-email) WITH_EMAIL=true; shift ;;
        --ids-only) IDS_ONLY=true; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option $1" ;;
        *) IFS=',' read -r -a _parts <<<"$1"; for p in "${_parts[@]}"; do [ -n "$p" ] && TENANTS+=("$p"); done; shift ;;
    esac
done
[ -n "$CONTEXT" ] || { usage >&2; die "--context is required"; }
case "$DISCOVER" in children|recursive|all) ;; *) die "--discover must be children, recursive or all" ;; esac
command -v jq >/dev/null || die "jq is required"
command -v "$OCTO_CLI" >/dev/null || die "octo-cli not found (set OCTO_CLI)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/secret-role-check.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# octo-cli prints a banner before the JSON; keep only the JSON document (starts with '{' or '[').
json_only() { sed -n '/^[[:space:]]*[[{]/,$p'; }

"$OCTO_CLI" --context "$CONTEXT" -c AuthStatus >/dev/null 2>&1 || die "context '$CONTEXT' is not logged in (octo-cli --context $CONTEXT -c LogIn -i)"

if [ ${#TENANTS[@]} -eq 0 ]; then
    case "$DISCOVER" in
        children) disc=(-c GetTenants) ;;
        recursive) disc=(-c GetTenants -r) ;;
        all) disc=(-c GetTenants -a) ;;
    esac
    "$OCTO_CLI" --context "$CONTEXT" "${disc[@]}" 2>/dev/null | json_only >"$WORK/tenants.json" \
        || die "tenant discovery failed (try --discover children or pass tenants)"
    while IFS= read -r t; do [ -n "$t" ] && TENANTS+=("$t"); done \
        < <(jq -r '.[] | (.tenantId // .tenantid // .TenantId // empty)' "$WORK/tenants.json" | sort -u)
    ANCHOR="$("$OCTO_CLI" --context "$CONTEXT" -c GetUsers 2>/dev/null | sed -n 's/^Using tenant: \([^ ]*\).*/\1/p' | head -1 || true)"
    [ -n "$ANCHOR" ] && TENANTS=("$ANCHOR" "${TENANTS[@]}")
fi
[ ${#TENANTS[@]} -gt 0 ] || die "no tenants to check"

# Never selects clientSecrets or any other secret attribute. Role edges are read from the role side (generic inbound
# AssignedRole associations) and group membership from the group side: one query per tenant, no per-entity lookups.
A='associations(roleId: "System.Identity/AssignedRole", direction: INBOUND, first: 5000'
M='associations(roleId: "System.Identity/GroupMember", direction: OUTBOUND, first: 5000'
read -r -d '' QUERY <<GQL || true
{
  runtime {
    roles: systemIdentityRole(first: 1000) { items { rtId name
      users: $A, ckId: "System.Identity/User") { items { rtId } }
      groups: $A, ckId: "System.Identity/Group") { items { rtId } }
      clients: $A, ckId: "System.Identity/Client") { items { rtId } } } }
    groups: systemIdentityGroup(first: 1000) { items { rtId groupName
      users: $M, ckId: "System.Identity/User") { items { rtId } }
      clients: $M, ckId: "System.Identity/Client") { items { rtId } }
      mappings: $M, ckId: "System.Identity/ExternalTenantUserMapping") { items { rtId } }
      children: associations(roleId: "System.Identity/ChildGroup", direction: OUTBOUND, first: 1000, ckId: "System.Identity/Group") { items { rtId } } } }
    users: systemIdentityUser(first: 5000) { items { rtId userName } }
    clients: systemIdentityClient(first: 2000) { items { rtId clientId } }
    mappings: systemIdentityExternalTenantUserMapping(first: 2000) { items { rtId sourceTenantId sourceUserName mappedRoleIds } }
  }
}
GQL

# Effective roles: direct roles + roles of every group the subject is a direct member of; a group's roles include those
# of its child groups (GroupRoleResolver / SecretManagementGrantPlanner semantics, depth-limited, cycle-safe).
read -r -d '' EVAL_JQ <<'JQ' || true
.data.runtime as $r
| ($r.roles.items | map({key: .rtId, value: .name}) | from_entries) as $roleName
| ($r.groups.items | map({key: .rtId, value: .}) | from_entries) as $groups
| def direct($kind): reduce ($r.roles.items[] | . as $role | ($role[$kind].items // [])[] | {s: .rtId, n: $role.name})
      as $e ({}; .[$e.s] += [$e.n]);
  (direct("users")) as $userRoles | (direct("clients")) as $clientRoles | (direct("groups")) as $groupOwn
| def groupRoles($id; $depth):
    if $depth > 10 or ($groups[$id] == null) then []
    else ($groupOwn[$id] // []) + ($groups[$id].children.items | map(groupRoles(.rtId; $depth + 1)) | add // [])
    end;
  def viaGroups($kind; $id):
    [ $r.groups.items[] | select(any(.[$kind].items[]?; .rtId == $id)) | groupRoles(.rtId; 0) ] | add // [];
  def mask: if $withEmail or (test("@") | not) then . else (.[0:3] + "***@" + (split("@") | last)) end;
  [ ($r.users.items[] | . as $u | {kind: "user", id: .rtId, name: ((.userName // .rtId) | mask),
        roles: (($userRoles[$u.rtId] // []) + viaGroups("users"; $u.rtId) | unique)}),
    ($r.clients.items[] | . as $c | {kind: "client", id: .rtId, name: .clientId,
        roles: (($clientRoles[$c.rtId] // []) + viaGroups("clients"; $c.rtId) | unique)}),
    ($r.mappings.items[] | . as $m | {kind: "mapping", id: .rtId,
        name: ((.sourceTenantId // "?") + "/" + ((.sourceUserName // "?") | mask)),
        roles: (((.mappedRoleIds // []) | map($roleName[.] // .)) + viaGroups("mappings"; $m.rtId) | unique)}) ] as $subjects
| (($r.roles.items | map(.rtId) | index($secretRoleId)) != null) as $roleExists
| if ($roleExists | not) then [$tenant, "tenant", "-", "-", "-", "-", "NO-ROLE"]
  else
    ($subjects[] | (.roles | index("SecretManagement") != null) as $sm
         | ((.roles | index("TenantManagement") != null) or (.roles | index("UserManagement") != null)) as $today
         | select($sm or $today)
         | [$tenant, .kind, .id, (if $ids then "-" else .name end), (if $sm then "yes" else "no" end), (if $today then "yes" else "no" end),
            (if $sm then "HOLDS" else "LOSES" end)])
  end
| @tsv
JQ

ERRORS=0
printf 'tenant\tkind\tid\tname\tsecret_management\ttoday_tm_or_um\tclass\n'
for t in "${TENANTS[@]}"; do
    info "Checking tenant '$t' ..."
    if ! "$OCTO_CLI" --context "$CONTEXT" -c GraphQl -tid "$t" -q "$QUERY" 2>/dev/null | json_only >"$WORK/$t.json" \
        || ! jq -e '.data.runtime.roles' "$WORK/$t.json" >/dev/null 2>&1; then
        printf '%s\ttenant\t-\t-\t-\t-\tERROR\n' "$t"
        ERRORS=$((ERRORS + 1))
        continue
    fi
    jq -r --arg tenant "$t" --arg secretRoleId "$SECRET_ROLE_ID" --argjson withEmail "$WITH_EMAIL" --argjson ids "$IDS_ONLY" "$EVAL_JQ" \
        "$WORK/$t.json" | tee -a "$WORK/rows.tsv"
done

touch "$WORK/rows.tsv"
{
    echo
    echo "# summary per tenant: holders of SecretManagement / subjects that lose API secret writes under Enforce"
    awk -F'\t' '{ t[$1] = 1; c[$1 SUBSEP $7]++ }
        END { for (k in t) printf "# %-28s holds=%d loses=%d%s\n", k, c[k SUBSEP "HOLDS"], c[k SUBSEP "LOSES"],
                (c[k SUBSEP "NO-ROLE"] ? " ROLE-MISSING" : "") }' "$WORK/rows.tsv" | sort
} >&2

FINDINGS="$(awk -F'\t' '$7 == "LOSES" || $7 == "NO-ROLE"' "$WORK/rows.tsv" | wc -l | tr -d ' ')"
if [ "$ERRORS" -gt 0 ]; then info "Result: $ERRORS tenant(s) not readable -- incomplete (exit 1)"; exit 1; fi
if [ "$FINDINGS" -gt 0 ]; then info "Result: $FINDINGS finding(s) (exit 2)"; exit 2; fi
info "Result: no findings (exit 0)"
exit 0
