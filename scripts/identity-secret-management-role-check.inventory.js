// identity-secret-management-role-check.inventory.js -- READ-ONLY SecretManagement inventory (AB#5861, AB#8155).
//
// Run by identity-secret-management-role-check.sh inside mongosh. Expects the globals `conn` (a connection opened with
// readPreference=secondaryPreferred) and `PARAMS` ({ tenants: string[], withEmail: bool, idsOnly: bool }).
// Uses read operations only: find() with a projection, toArray()/forEach(), getDBNames(). The shell script refuses to
// run this file when it contains a write-capable call (see the guard there).
//
// Secret material is never loaded: every find() projects the few attributes the inventory needs, so password hashes,
// security stamps, client secrets and tokens never leave the database.
//
// Output: one line per row, "ROW<TAB>tenant<TAB>kind<TAB>id<TAB>name<TAB>secret_management<TAB>today_tm_or_um<TAB>class",
// then "END" (the shell script treats a missing END as an incomplete run).

const SECRET_ROLE_ID = "660000000000000000000060";
const ASSIGNED_ROLE = "System.Identity/AssignedRole";
const GROUP_MEMBER = "System.Identity/GroupMember";
const CHILD_GROUP = "System.Identity/ChildGroup";

const clean = s => String(s).split(/[\t\r\n]/).join(" ");
const mask = s => (PARAMS.withEmail || !String(s).includes("@")) ? String(s) : String(s).slice(0, 3) + "***@" + String(s).split("@").pop();
const emit = cols => print("ROW\t" + cols.map(clean).join("\t"));

const systemDb = conn.getSiblingDB("octosystem");
const allTenants = [{ tenantId: "octosystem", db: "octosystem" }].concat(
    systemDb.getCollection("RtEntity_SystemTenant")
        .find({}, { "attributes.tenantId": 1, "attributes.databaseName": 1 })
        .toArray()
        .map(t => ({ tenantId: t.attributes.tenantId, db: t.attributes.databaseName || t.attributes.tenantId })));
const byId = {};
allTenants.forEach(t => { byId[t.tenantId] = t; });
const selected = PARAMS.tenants.length
    ? PARAMS.tenants.map(id => byId[id] || { tenantId: id, db: null })
    : allTenants.slice().sort((a, b) => a.tenantId < b.tenantId ? -1 : a.tenantId > b.tenantId ? 1 : 0);
const existing = new Set(conn.getMongo().getDBNames());

for (const t of selected) {
    if (!t.db || !existing.has(t.db)) { emit([t.tenantId, "tenant", "-", "-", "-", "-", "ERROR"]); continue; }
    const d = conn.getSiblingDB(t.db);

    const roleName = {};
    d.getCollection("RtEntity_SystemIdentityRole").find({}, { "attributes.name": 1 })
        .forEach(r => { roleName[String(r._id)] = r.attributes.name; });
    if (!roleName[SECRET_ROLE_ID]) { emit([t.tenantId, "tenant", "-", "-", "-", "-", "NO-ROLE"]); continue; }

    const groupIds = new Set();
    d.getCollection("RtEntity_SystemIdentityGroup").find({}, { _id: 1 }).forEach(g => groupIds.add(String(g._id)));

    // Edges: AssignedRole subject -> role, GroupMember group -> member, ChildGroup parent -> child.
    const assigned = {}, memberOf = {}, children = {};
    const push = (map, key, value) => { (map[key] = map[key] || []).push(value); };
    d.getCollection("RtAssociation")
        .find({ associationRoleId: { $in: [ASSIGNED_ROLE, GROUP_MEMBER, CHILD_GROUP] } },
              { originRtId: 1, targetRtId: 1, associationRoleId: 1 })
        .forEach(a => {
            const origin = String(a.originRtId), target = String(a.targetRtId);
            if (a.associationRoleId === ASSIGNED_ROLE) push(assigned, origin, roleName[target] || target);
            else if (a.associationRoleId === GROUP_MEMBER) push(memberOf, target, origin);
            else push(children, origin, target);
        });

    // A group's roles include those of its child groups (GroupRoleResolver semantics, depth-limited, cycle-safe).
    const groupRoles = (id, depth, seen) => {
        if (depth > 10 || seen.has(id) || !groupIds.has(id)) return [];
        seen.add(id);
        let roles = (assigned[id] || []).slice();
        for (const child of (children[id] || [])) roles = roles.concat(groupRoles(child, depth + 1, seen));
        return roles;
    };
    const effective = (id, direct) => {
        let roles = direct.slice();
        for (const g of (memberOf[id] || [])) roles = roles.concat(groupRoles(g, 0, new Set()));
        return new Set(roles);
    };

    const rows = [];
    const add = (kind, id, name, direct) => {
        const roles = effective(id, direct);
        const sm = roles.has("SecretManagement");
        const today = roles.has("TenantManagement") || roles.has("UserManagement");
        if (!sm && !today) return;
        rows.push([t.tenantId, kind, id, PARAMS.idsOnly ? "-" : name, sm ? "yes" : "no", today ? "yes" : "no", sm ? "HOLDS" : "LOSES"]);
    };
    d.getCollection("RtEntity_SystemIdentityUser").find({}, { "attributes.userName": 1 })
        .forEach(u => add("user", String(u._id), mask(u.attributes.userName || String(u._id)), assigned[String(u._id)] || []));
    d.getCollection("RtEntity_SystemIdentityClient").find({}, { "attributes.clientId": 1 })
        .forEach(c => add("client", String(c._id), c.attributes.clientId || String(c._id), assigned[String(c._id)] || []));
    d.getCollection("RtEntity_SystemIdentityExternalTenantUserMapping")
        .find({}, { "attributes.sourceTenantId": 1, "attributes.sourceUserName": 1, "attributes.mappedRoleIds": 1 })
        .forEach(m => add("mapping", String(m._id),
            (m.attributes.sourceTenantId || "?") + "/" + mask(m.attributes.sourceUserName || "?"),
            (m.attributes.mappedRoleIds || []).map(r => roleName[String(r)] || String(r))));
    rows.forEach(emit);
}
print("END");
