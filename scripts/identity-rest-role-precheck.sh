#!/usr/bin/env bash
# identity-rest-role-precheck.sh -- READ-ONLY precheck for AB#5859.
#
# The identity tenant REST API ({tenant}/v1/...) requires tenant roles since AB#5859:
#   UserManagement                    users, roles, groups, external tenant user mappings, data permissions, ...
#   TenantManagement|UserManagement   clients, API resources/scopes/secrets, identity providers, ...
# This script lists, per tenant, the subjects that will lose identity administration once
# RoleEnforcement=Enforce is rolled out, and optionally aggregates the "would be denied" lines of a
# saved identity log (Warn phase).
#
# It only runs octo-cli READ commands (AuthStatus, ListContexts, GetTenants, GetRoles, GetGroups,
# GetUsers, GetClients, GetExternalTenantUserMappings). It never writes to an environment, never
# calls kubectl and never prints tokens, client secrets or (unless --with-email) e-mail addresses.
#
# Requirements: bash >= 3.2, octo-cli, jq.
# Exit codes: 0 = no findings, 2 = findings, 1 = error (incl. tenants that could not be checked).

set -euo pipefail

OCTO_CLI="${OCTO_CLI:-octo-cli}"
SCRIPT_NAME="$(basename "$0")"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME --context <ctx> [options] [tenant ...]
       $SCRIPT_NAME --warn-log <file> [--context <ctx> [tenant ...]] [options]

Read-only precheck for the identity REST role enforcement (AB#5859).

Tenants
  tenant ...               Tenants to check (space or comma separated). Default: the tenant of
                           --context plus the tenants discovered with GetTenants (see --discover).
  --discover <mode>        children | recursive | all   (default: recursive)
                           all = every tenant of the installation; only works when --context points
                           to the system tenant (octosystem).

Contexts (octo-cli has no per-call tenant switch; the tenant comes from the context)
  --context <ctx>          Anchor context. Defines the installation (identity URL) and is used for
                           its own tenant and for tenant discovery.
  --map <tenant>=<ctx>     Use this context for that tenant (repeatable). Otherwise the script looks
                           for a context with the same identity URL and that tenant, preferring the
                           name <prefix>_<tenant> (e.g. test-2_meshtest for --context test-2_octosystem).
                           Tenants without a usable context are reported as SKIPPED (exit 1).

Output (TSV on stdout, progress on stderr)
  --all                    Also list informational rows (users without UserManagement/TenantManagement
                           and without other admin roles). By default only their count is printed.
  --with-email             Show user names / external user names that are e-mail addresses unmasked.
  --admin-role-regex <re>  Roles that mark a subject as "administrative" (jq/PCRE regex).
                           Default: 'Management\$'  (UserManagement/TenantManagement are always excluded)

Warn log
  --warn-log <file>        Parse a saved identity log (e.g. kubectl logs ... > file after a
                           RoleEnforcement=Warn phase) for "would be denied with RoleEnforcement=Enforce
                           (AB#5859)" lines (and Enforce-mode "denied" lines) and aggregate them by
                           tenant/subject/client/method/path. The file is only read.

Misc
  --dry-run                Only print the octo-cli commands that would run; run nothing.
  -h, --help               This help.

Examples
  $SCRIPT_NAME --context test-2_octosystem
  $SCRIPT_NAME --context test-2_octosystem meshtest energyiq --map energyiq=my-energyiq-ctx
  $SCRIPT_NAME --context prod-1_octosystem --discover all --all
  $SCRIPT_NAME --warn-log identity-warn.log --context test-2_octosystem
  $SCRIPT_NAME --context test-2_octosystem --dry-run

Exit codes: 0 = no findings, 2 = findings, 1 = error / incomplete check.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$*" >&2; }

# ---------------------------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------------------------
CONTEXT=""
DISCOVER="recursive"
SHOW_ALL=false
WITH_EMAIL=false
DRY_RUN=false
WARN_LOG=""
ADMIN_RE='Management$'
MAPS=()
TENANTS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --context) [ $# -ge 2 ] || die "--context needs a value"; CONTEXT="$2"; shift 2 ;;
        --map) [ $# -ge 2 ] || die "--map needs <tenant>=<ctx>"
               case "$2" in *=?*) ;; *) die "--map needs <tenant>=<ctx>, got '$2'" ;; esac
               MAPS+=("$2"); shift 2 ;;
        --discover) [ $# -ge 2 ] || die "--discover needs a value"; DISCOVER="$2"; shift 2
                    case "$DISCOVER" in children|recursive|all) ;; *) die "--discover must be children|recursive|all" ;; esac ;;
        --all) SHOW_ALL=true; shift ;;
        --with-email) WITH_EMAIL=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --warn-log) [ $# -ge 2 ] || die "--warn-log needs a file"; WARN_LOG="$2"; shift 2 ;;
        --admin-role-regex) [ $# -ge 2 ] || die "--admin-role-regex needs a value"; ADMIN_RE="$2"; shift 2 ;;
        --) shift; while [ $# -gt 0 ]; do TENANTS+=("$1"); shift; done ;;
        -*) die "unknown option '$1' (see -h)" ;;
        *) TENANTS+=("$1"); shift ;;
    esac
done

# Allow comma-separated tenant lists.
if [ ${#TENANTS[@]} -gt 0 ]; then
    _split=()
    for _t in "${TENANTS[@]}"; do
        IFS=',' read -r -a _parts <<<"$_t"
        for _p in ${_parts[@]+"${_parts[@]}"}; do [ -n "$_p" ] && _split+=("$_p"); done
    done
    TENANTS=(${_split[@]+"${_split[@]}"})
fi

[ -n "$CONTEXT" ] || [ -n "$WARN_LOG" ] || { usage >&2; die "--context or --warn-log is required"; }
if [ -n "$WARN_LOG" ] && ! $DRY_RUN; then
    [ -r "$WARN_LOG" ] || die "warn log '$WARN_LOG' is not readable"
fi
command -v jq >/dev/null 2>&1 || die "jq not found"
if [ -n "$CONTEXT" ] && ! $DRY_RUN; then
    command -v "$OCTO_CLI" >/dev/null 2>&1 || die "octo-cli not found (set OCTO_CLI=/path/to/octo-cli)"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/idprecheck.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
: >"$WORK/rows.tsv"
: >"$WORK/usermap.tsv"

ERRORS=0

# ---------------------------------------------------------------------------------------------
# octo-cli helpers
# ---------------------------------------------------------------------------------------------

# Prints the command (dry run) or runs it. Output is ALWAYS filtered through grep -v eyJ so that no
# JWT can reach a terminal or a variable. Sets OCTO_RC.
OCTO_OUT=""
OCTO_RC=0
octo() {
    local ctx="$1"; shift
    if $DRY_RUN; then
        printf '%s --context %s' "$OCTO_CLI" "$ctx"
        printf ' %s' "$@"
        printf '\n'
        OCTO_OUT=""; OCTO_RC=0
        return 0
    fi
    set +e
    OCTO_OUT="$("$OCTO_CLI" --context "$ctx" "$@" 2>&1 | grep -v eyJ)"
    OCTO_RC=$?
    set -e
    # grep -v exits 1 when every line was filtered; octo-cli always prints a banner, so treat
    # rc 1 together with empty output as an error as well.
    return 0
}

# Extracts the JSON payload from octo-cli output (banner and log lines come first). Also handles
# the "OK: [...]" form that octo-cli prints when the SDK fails to deserialize a 200 response
# (seen with GetGroups: the service returns a bare array, the SDK expects GroupsResult).
extract_json() {
    awk '
        started { print; next }
        /^OK: [[{]/ { sub(/^OK: /, ""); print; exit }
        /^[[{]/ { started = 1; print; next }
    '
}

# Prints one short, sanitized error line (never a whole response body).
short_error() {
    printf '%s\n' "$1" | grep -iE 'error|fail|forbidden|unauthori|denied|exception|status|not found|refresh' \
        | head -n 2 | cut -c1-240 | sed 's/^/    /' >&2 || true
}

# octo_json <ctx> <args...>: runs a read command and stores normalized JSON (array) in JSON_OUT.
# Returns 1 on error.
JSON_OUT="[]"
octo_json() {
    local ctx="$1"; shift
    octo "$ctx" "$@"
    if $DRY_RUN; then JSON_OUT="[]"; return 0; fi
    local payload
    payload="$(printf '%s\n' "$OCTO_OUT" | extract_json)"
    if [ -n "$payload" ] && printf '%s' "$payload" | jq -e 'type == "array" or type == "object"' >/dev/null 2>&1; then
        # Drop anything secret-like right away; lower-case all keys (octo-cli prints PascalCase,
        # the "OK:" fallback camelCase).
        JSON_OUT="$(printf '%s' "$payload" | jq -c '
            def lc: if type == "object" then with_entries(.key |= ascii_downcase | .value |= lc)
                    elif type == "array" then map(lc) else . end;
            (if type == "array" then . else [.] end) | lc
            | map(del(.clientsecret, .password, .secret, .secrets, .accesstoken, .refreshtoken))')"
        if [ "$OCTO_RC" -ne 0 ]; then
            info "  note: '$*' exited with $OCTO_RC but returned a parsable 200 body (octo-cli/SDK deserialization issue) -- using it"
        fi
        return 0
    fi
    if [ "$OCTO_RC" -eq 0 ] && printf '%s\n' "$OCTO_OUT" | grep -qiE 'no .* (has|have) been returned'; then
        JSON_OUT="[]"
        return 0
    fi
    info "  ERROR: '$*' failed (rc=$OCTO_RC) on context '$ctx':"
    short_error "$OCTO_OUT"
    return 1
}

# Silent token refresh. Output is filtered (grep -v eyJ) and never printed.
auth_ok() {
    local ctx="$1"
    octo "$ctx" -c AuthStatus
    if $DRY_RUN; then return 0; fi
    if printf '%s\n' "$OCTO_OUT" | grep -qE 'Access token is valid|Refresh successful'; then
        return 0
    fi
    info "  ERROR: context '$ctx' is not authenticated (refresh failed). Run:"
    info "    $OCTO_CLI --context $ctx -c LogIn -i --if-needed"
    return 1
}

# ---------------------------------------------------------------------------------------------
# Context resolution
# ---------------------------------------------------------------------------------------------
CONTEXTS_JSON="[]"
ANCHOR_TENANT=""
ANCHOR_IDENTITY=""

load_contexts() {
    if $DRY_RUN; then
        printf '%s -c ListContexts -j\n' "$OCTO_CLI"
        ANCHOR_TENANT="<tenant of $CONTEXT>"
        return 0
    fi
    local out
    set +e
    out="$("$OCTO_CLI" -c ListContexts -j 2>&1 | grep -v eyJ)"
    set -e
    # ListContexts -j only exposes name/tenant/service URLs/auth status, never tokens. Keep only
    # what we need anyway.
    CONTEXTS_JSON="$(printf '%s\n' "$out" | extract_json | jq -c '
        map({name, tenant: (.tenant // ""), identity: ((.services.identity // "") | ascii_downcase | sub("/+$"; ""))})' 2>/dev/null)" \
        || die "could not read octo-cli contexts (ListContexts -j)"
    ANCHOR_TENANT="$(printf '%s' "$CONTEXTS_JSON" | jq -r --arg n "$CONTEXT" \
        'map(select((.name | ascii_downcase) == ($n | ascii_downcase))) | .[0].tenant // empty')"
    ANCHOR_IDENTITY="$(printf '%s' "$CONTEXTS_JSON" | jq -r --arg n "$CONTEXT" \
        'map(select((.name | ascii_downcase) == ($n | ascii_downcase))) | .[0].identity // empty')"
    [ -n "$ANCHOR_TENANT" ] || die "context '$CONTEXT' not found or has no tenant (octo-cli -c ListContexts)"
}

# Prints the context to use for a tenant, or nothing.
context_for_tenant() {
    local tenant="$1" m
    for m in ${MAPS[@]+"${MAPS[@]}"}; do
        if [ "${m%%=*}" = "$tenant" ]; then printf '%s\n' "${m#*=}"; return 0; fi
    done
    if $DRY_RUN; then
        if [ "$tenant" = "$ANCHOR_TENANT" ]; then printf '%s\n' "$CONTEXT"; else printf '<context for %s>\n' "$tenant"; fi
        return 0
    fi
    if [ "$(printf '%s' "$tenant" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$ANCHOR_TENANT" | tr '[:upper:]' '[:lower:]')" ]; then
        printf '%s\n' "$CONTEXT"; return 0
    fi
    local prefix="${CONTEXT%_"$ANCHOR_TENANT"}"
    [ "$prefix" = "$CONTEXT" ] && prefix="${CONTEXT%%_*}"
    printf '%s' "$CONTEXTS_JSON" | jq -r --arg t "$tenant" --arg id "$ANCHOR_IDENTITY" --arg pref "${prefix}_${tenant}" '
        map(select((.tenant | ascii_downcase) == ($t | ascii_downcase) and .identity == $id))
        | (map(select((.name | ascii_downcase) == ($pref | ascii_downcase))) + .) | .[0].name // empty'
}

# ---------------------------------------------------------------------------------------------
# Per-tenant analysis
# ---------------------------------------------------------------------------------------------
# Emits TSV rows: tenant kind id name display roles groups class finding
# class: FINDING (counts for exit 2) | REVIEW | INFO
# shellcheck disable=SC2016  # jq program, $vars are jq variables
ANALYZE_JQ='
def lcset: map(ascii_downcase);
def mask: if $withEmail or (type != "string") then . elif test("@") then (.[0:2] + "***@***") else . end;
($roles | map({key: (.id | tostring), value: .name}) | from_entries) as $rn
| def rname: $rn[tostring] // ("?" + tostring);
  def direct_groups($field; $id): [$groups[] | select(((.[$field] // []) | index($id)) != null) | .id];
  def by_name($names): [$groups[] | select(.groupname as $g | ($names // []) | index($g) != null) | .id];
  # A member of child group C inherits the roles of every group P with C in P.membergroupids (transitively).
  def closure:
    def step: . as $s | ($s + [$groups[] | select(any((.membergroupids // [])[]; . as $m | $s | index($m) != null)) | .id]) | unique;
    unique | until(. as $s | (step | length) == ($s | length); step);
  def group_roles($gids): [$groups[] | select(.id as $i | $gids | index($i) != null) | (.roleids // [])[] | rname];
  def group_names($gids): [$groups[] | select(.id as $i | $gids | index($i) != null) | .groupname] | unique;
  def classify($kind):
    (.roles | map(select(. == "UserManagement" or . == "TenantManagement")) | length > 0) as $ident
    | (.roles | map(select(. != "UserManagement" and . != "TenantManagement" and test($adminRe)))) as $adm
    | if $ident then .class = "OK" | .finding = "has identity role"
      elif $kind == "client" then
        if (.roles | length) > 0 then .class = "FINDING" | .finding = "client roles lack UserManagement/TenantManagement; identity REST calls will get 403"
        else .class = "REVIEW" | .finding = "client_credentials client without group-inherited roles; DIRECT client roles are not visible via octo-cli -- check in Studio" end
      elif ($adm | length) > 0 then .class = "FINDING" | .finding = "admin roles (" + ($adm | join(",")) + ") but no UserManagement/TenantManagement; identity admin pages/API will get 403"
      else .class = "INFO" | .finding = "no UserManagement/TenantManagement (and no other admin role)" end;
  (
    [ $users[] | . as $u
      | (direct_groups("memberuserids"; $u.userid) | closure) as $g
      | { kind: "user", id: $u.userid, name: ($u.name | mask),
          display: ([$u.firstname, $u.lastname] | map(select(. != null and . != "")) | join(" ") | mask),
          roles: (group_roles($g) | unique), groups: group_names($g),
          note: " [user roles = group-inherited only; direct user roles not visible via octo-cli]" }
      | classify("user") ]
  + [ $ext[] | . as $x
      | ((direct_groups("memberexternaluserids"; $x.id) + by_name($x.groupnames)) | closure) as $g
      | { kind: "external", id: $x.id, name: ($x.sourceusername | mask),
          display: ("from tenant " + ($x.sourcetenantid // "?")),
          roles: ((($x.roleids // []) | map(rname)) + group_roles($g) | unique), groups: group_names($g), note: "" }
      | classify("external") ]
  + [ $clients[] | select((.allowedgranttypes // []) | index("client_credentials") != null) | . as $c
      | (direct_groups("memberclientids"; $c.rtid) | closure) as $g
      | { kind: "client", id: $c.clientid, name: $c.clientid,
          display: (($c.clientname // "") + (if $c.provisionedbyparenttenantid then " (mirror of " + $c.provisionedbyparenttenantid + ")" else "" end)),
          roles: (group_roles($g) | unique), groups: group_names($g),
          note: " [client roles = group-inherited only; direct client roles not visible via octo-cli]" }
      | classify("client") ]
  )
  | .[]
  | [$tenant, .kind, (.id // ""), (.name // ""), (.display // ""), (.roles | join(",")), (.groups | join(",")), .class,
     (.finding + (if .class == "OK" then "" else .note end))]
  | map(tostring | gsub("[\t\n\r]"; " "))
  | @tsv
'

# shellcheck disable=SC2016
USERMAP_JQ='
def mask: if $withEmail or (type != "string") then . elif test("@") then (.[0:2] + "***@***") else . end;
$users[] | [$tenant, (.userid // ""), ((.name // "") | mask)] | @tsv'

check_tenant() {
    local tenant="$1" ctx
    ctx="$(context_for_tenant "$tenant")"
    if [ -z "$ctx" ]; then
        info "[$tenant] SKIPPED: no octo-cli context for tenant '$tenant' on ${ANCHOR_IDENTITY:-this installation}."
        info "    Create one (local CLI config only), e.g.: $OCTO_CLI -c AddContext -n <env>_$tenant ... ; then LogIn -i, or pass --map $tenant=<ctx>"
        printf '%s\ttenant\t%s\t\t\t\t\tERROR\tSKIPPED: no octo-cli context for this tenant\n' "$tenant" "$tenant" >>"$WORK/rows.tsv"
        ERRORS=$((ERRORS + 1))
        return 0
    fi
    info "[$tenant] context '$ctx'"
    if ! auth_ok "$ctx"; then
        printf '%s\ttenant\t%s\t\t\t\t\tERROR\tSKIPPED: context %s not authenticated\n' "$tenant" "$tenant" "$ctx" >>"$WORK/rows.tsv"
        ERRORS=$((ERRORS + 1)); return 0
    fi
    local roles groups users clients ext
    if ! octo_json "$ctx" -c GetRoles; then ERRORS=$((ERRORS + 1)); return 0; fi; roles="$JSON_OUT"
    if ! octo_json "$ctx" -c GetGroups; then ERRORS=$((ERRORS + 1)); return 0; fi; groups="$JSON_OUT"
    if ! octo_json "$ctx" -c GetUsers; then ERRORS=$((ERRORS + 1)); return 0; fi; users="$JSON_OUT"
    if ! octo_json "$ctx" -c GetClients; then ERRORS=$((ERRORS + 1)); return 0; fi; clients="$JSON_OUT"
    if ! octo_json "$ctx" -c GetExternalTenantUserMappings; then ERRORS=$((ERRORS + 1)); return 0; fi; ext="$JSON_OUT"
    $DRY_RUN && return 0

    jq -nr --arg tenant "$tenant" --argjson withEmail "$WITH_EMAIL" --arg adminRe "$ADMIN_RE" \
        --argjson roles "$roles" --argjson groups "$groups" --argjson users "$users" \
        --argjson clients "$clients" --argjson ext "$ext" "$ANALYZE_JQ" >>"$WORK/rows.tsv" \
        || { info "  ERROR: analysis failed for tenant '$tenant'"; ERRORS=$((ERRORS + 1)); return 0; }
    jq -nr --arg tenant "$tenant" --argjson withEmail "$WITH_EMAIL" --argjson users "$users" "$USERMAP_JQ" \
        >>"$WORK/usermap.tsv" || true
}

# ---------------------------------------------------------------------------------------------
# Warn log
# ---------------------------------------------------------------------------------------------
# Output columns: count tenant event subject user client method path required
parse_warn_log() {
    local file="$1"
    # 1) only lines of AB#5859; 2) drop message-template fields of structured (JSON) logs so the
    #    rendered message is matched, not "{Method} {Path}"; 3) extract fields ('|' separated).
    grep -F 'AB#5859' "$file" \
        | sed -E 's/"(MessageTemplate|messageTemplate|Template|template|@mt|@t)": *"[^"]*"//g' \
        | sed -nE \
            -e 's/.*allowed by RoleEnforcement=Warn: ([^ ]+) ([^ ]+) in tenant ([^ ]*) by subject ([^ ]*) \/ client ([^ ,]*), required any of \[([^]]*)\].*/\3|would-deny|\4|\5|\1|\2|\6/p' \
            -e 's/.*Identity API call denied, required role missing: ([^ ]+) ([^ ]+) in tenant ([^ ]*) by subject ([^ ]*) \/ client ([^ ,]*), required any of \[([^]]*)\].*/\3|denied|\4|\5|\1|\2|\6/p' \
            -e "s/.*outside the caller's tenant subtree allowed by RoleEnforcement=Warn: caller tenant ([^ ,]*), target tenant ([^ ,]*), ([^ ]+) ([^ .]+).*/\\2|would-deny-provisioning|caller-tenant:\\1||\\3|\\4|subtree/p" \
            -e 's/.*token tenant ([^ ]+) does not match route tenant ([^ :]*): ([^ ]+) ([^ ]+) by subject ([^ ]*) \/ client ([^ ,]*) \(AB#5859\).*/\2|denied-tenant-mismatch|\5|\6|\3|\4|token-tenant:\1/p' \
        | grep -vE '\|\{' || true
}

warn_log_report() {
    local file="$1"
    info "Parsing warn log '$file' ..."
    parse_warn_log "$file" >"$WORK/warn.raw"
    local total
    total="$(wc -l <"$WORK/warn.raw" | tr -d ' ')"
    echo
    echo "# warn-log: $total matching line(s) in $(basename "$file")"
    printf 'count\ttenant\tevent\tsubject\tuser\tclient\tmethod\tpath\trequired\n'
    [ "$total" -gt 0 ] || return 0
    awk -F'|' -v OFS='\t' -v withEmail="$WITH_EMAIL" '
        FILENAME == ARGV[1] { split($0, a, "\t"); umap[tolower(a[1]) SUBSEP a[2]] = a[3]; next }
        {
            tenant = $1; path = $6
            sub(/\?.*/, "", path)
            n = split(path, seg, "/"); p = ""
            for (i = 2; i <= n; i++) {
                s = seg[i]
                if (s ~ /^[0-9a-fA-F]{24}$/ || s ~ /^[0-9a-fA-F-]{36}$/) s = "{id}"
                else if (withEmail != "true" && s ~ /@|%40/) s = "{user}"
                p = p "/" s
            }
            subj = $3; if (subj == "" || subj == "(null)") subj = "-"
            cli = $4; if (cli == "" || cli == "(null)") cli = "-"
            user = umap[tolower(tenant) SUBSEP subj]; if (user == "") user = "-"
            print tenant, $2, subj, user, cli, $5, p, $7
        }' "$WORK/usermap.tsv" "$WORK/warn.raw" \
        | sort | uniq -c | sort -rn \
        | awk -v OFS='\t' '{ c = $1; sub(/^ *[0-9]+ /, ""); print c, $0 }'
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
if [ -n "$CONTEXT" ]; then
    if $DRY_RUN; then info "# dry run: octo-cli commands that would run (nothing is executed)"; fi
    load_contexts
    if ! auth_ok "$CONTEXT"; then exit 1; fi

    if [ ${#TENANTS[@]} -eq 0 ]; then
        case "$DISCOVER" in
            children) disc_args=(-c GetTenants) ;;
            recursive) disc_args=(-c GetTenants -r) ;;
            all) disc_args=(-c GetTenants -a) ;;
        esac
        octo_json "$CONTEXT" "${disc_args[@]}" || die "tenant discovery failed (try --discover children or pass tenants explicitly)"
        TENANTS=("$ANCHOR_TENANT")
        if $DRY_RUN; then
            TENANTS+=("<each discovered tenant>")
        else
            while IFS= read -r t; do
                [ -n "$t" ] && TENANTS+=("$t")
            done < <(printf '%s' "$JSON_OUT" | jq -r '.[].tenantid // empty' | sort -u)
            # de-duplicate (anchor may be listed by --all)
            _uniq=()
            for t in "${TENANTS[@]}"; do
                _seen=false
                for u in ${_uniq[@]+"${_uniq[@]}"}; do [ "$u" = "$t" ] && _seen=true; done
                $_seen || _uniq+=("$t")
            done
            TENANTS=("${_uniq[@]}")
        fi
    fi
    info "Tenants: ${TENANTS[*]}"

    for t in "${TENANTS[@]}"; do
        if $DRY_RUN && [ "$t" = "<each discovered tenant>" ]; then
            ctx="<context for each discovered tenant>"
            for c in "-c AuthStatus" "-c GetRoles" "-c GetGroups" "-c GetUsers" "-c GetClients" "-c GetExternalTenantUserMappings"; do
                printf '%s --context %s %s\n' "$OCTO_CLI" "$ctx" "$c"
            done
            continue
        fi
        check_tenant "$t"
    done
fi

if $DRY_RUN; then
    [ -n "$WARN_LOG" ] && echo "# would parse warn log '$WARN_LOG' (local file, read only)"
    exit 0
fi

FINDINGS=0
if [ -n "$CONTEXT" ]; then
    printf 'tenant\tkind\tid\tname\tdisplay_name\troles\tgroups\tclass\tfinding\n'
    if $SHOW_ALL; then
        awk -F'\t' '$8 != "OK"' "$WORK/rows.tsv"
    else
        awk -F'\t' '$8 == "FINDING" || $8 == "REVIEW" || $8 == "ERROR"' "$WORK/rows.tsv"
    fi
    FINDINGS="$(awk -F'\t' '$8 == "FINDING"' "$WORK/rows.tsv" | wc -l | tr -d ' ')"
    {
        echo
        echo "# summary per tenant (users = local users + external tenant user mappings; clients = client_credentials only)"
        printf '# %-24s %8s %10s %9s %8s %7s %6s\n' tenant subjects identity findings review info error
        awk -F'\t' '
            { t[$1] = 1; n[$1]++; c[$1 SUBSEP $8]++ }
            END { for (k in t) printf "# %-24s %8d %10d %9d %8d %7d %6d\n", k,
                    n[k] - c[k SUBSEP "ERROR"], c[k SUBSEP "OK"], c[k SUBSEP "FINDING"],
                    c[k SUBSEP "REVIEW"], c[k SUBSEP "INFO"], c[k SUBSEP "ERROR"] }' "$WORK/rows.tsv" | sort
        if ! $SHOW_ALL; then echo "# INFO rows (no identity role, no other admin role) hidden; use --all to list them"; fi
        echo "# NOTE: direct user/client role assignments are not exposed by octo-cli; only group-inherited"
        echo "#       roles (incl. TenantOwners) and external-mapping roles are evaluated. See REVIEW rows."
    } >&2
fi

if [ -n "$WARN_LOG" ]; then
    warn_log_report "$WARN_LOG"
    WL="$(grep -cE '\|(would-deny|would-deny-provisioning)\|' "$WORK/warn.raw" || true)"
    FINDINGS=$((FINDINGS + ${WL:-0}))
fi

if [ "$ERRORS" -gt 0 ]; then
    info "Result: $ERRORS error(s) -- check incomplete (exit 1)"
    exit 1
fi
if [ "$FINDINGS" -gt 0 ]; then
    info "Result: $FINDINGS finding(s) (exit 2)"
    exit 2
fi
info "Result: no findings (exit 0)"
exit 0
