// identity-bootstrap-seed-check.inventory.js -- READ-ONLY check of the System.Identity.Bootstrap seed per tenant.
//
// Run by identity-bootstrap-seed-check.sh inside mongosh. Expects the globals `conn` (a connection opened with
// readPreference=secondaryPreferred) and `PARAMS` ({ systemDb: string, tenants: string[] }).
// Uses read operations only: find() with a projection, countDocuments(), toArray()/forEach(), getCollectionNames() and
// getDBNames(). The shell script refuses to run this file when it contains a write-capable call (see the guard there).
//
// Why: concurrent tenant seed imports on one shared import command could drop entities or associations of one tenant
// or write them into the session of another. This check lists, per tenant database, whether every seed entity of the
// blueprint exists exactly once under its own CK type, whether every seed association exists exactly once, and
// whether a seed entity carries a provisioning marker of a tenant it does not belong to.
//
// Secret material is never loaded: entity queries project _id and ckTypeId (and provisionedByParentTenantId for
// clients); client secrets are never read.
//
// Output: one line per finding, "ROW<TAB>tenant<TAB>kind<TAB>id<TAB>detail<TAB>class", one summary line per tenant,
// "SUM<TAB>tenant<TAB>present<TAB>expected<TAB>missing<TAB>unexpected<TAB>assocPresent<TAB>assocExpected<TAB>
// assocMissing<TAB>assocDuplicate", then "END" (the shell script treats a missing END as an incomplete run).
// Classes: MISSING (seed rtId in no entity collection of the tenant), DUPLICATE (seed rtId in more than one entity
// collection), TYPE-MISMATCH (seed rtId stored with another ckTypeId), FOREIGN-PROVISIONING
// (provisionedByParentTenantId names no ancestor of the tenant), ASSOC-MISSING, ASSOC-DUPLICATE,
// NO-DATABASE (tenant database not found). Present = the rtId exists in the tenant; unexpected = DUPLICATE,
// TYPE-MISMATCH or FOREIGN-PROVISIONING.

// Generated from src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data (blueprint 1.12.0);
// BootstrapSeedCheckManifestTests fails when the seed and this list differ.
const SEED_BLUEPRINT = "System.Identity.Bootstrap-1.12.0";
const SEED_ENTITIES = [
    { rtId: "660000000000000000000020", ckTypeId: "System.Identity/ApiResource" },
    { rtId: "660000000000000000000021", ckTypeId: "System.Identity/ApiResource" },
    { rtId: "660000000000000000000014", ckTypeId: "System.Identity/ApiScope" },
    { rtId: "660000000000000000000015", ckTypeId: "System.Identity/ApiScope" },
    { rtId: "660000000000000000000016", ckTypeId: "System.Identity/ApiScope" },
    { rtId: "660000000000000000000017", ckTypeId: "System.Identity/ApiScope" },
    { rtId: "660000000000000000000018", ckTypeId: "System.Identity/ApiScope" },
    { rtId: "660000000000000000000032", ckTypeId: "System.Identity/Client" },
    { rtId: "660000000000000000000033", ckTypeId: "System.Identity/Client" },
    { rtId: "660000000000000000000034", ckTypeId: "System.Identity/Client" },
    { rtId: "660000000000000000000031", ckTypeId: "System.Identity/Client" },
    { rtId: "660000000000000000000036", ckTypeId: "System.Identity/Client" },
    { rtId: "660000000000000000000030", ckTypeId: "System.Identity/Client" },
    { rtId: "660000000000000000000050", ckTypeId: "System.Identity/DataPermission" },
    { rtId: "660000000000000000000051", ckTypeId: "System.Identity/DataPolicy" },
    { rtId: "660000000000000000000052", ckTypeId: "System.Identity/DataPermission" },
    { rtId: "660000000000000000000053", ckTypeId: "System.Identity/DataPermission" },
    { rtId: "660000000000000000000054", ckTypeId: "System.Identity/DataPolicy" },
    { rtId: "660000000000000000000055", ckTypeId: "System.Identity/DataPolicy" },
    { rtId: "660000000000000000000040", ckTypeId: "System.Identity/Group" },
    { rtId: "66000000000000000000000f", ckTypeId: "System.Identity/IdentityResource" },
    { rtId: "660000000000000000000010", ckTypeId: "System.Identity/IdentityResource" },
    { rtId: "660000000000000000000011", ckTypeId: "System.Identity/IdentityResource" },
    { rtId: "660000000000000000000012", ckTypeId: "System.Identity/IdentityResource" },
    { rtId: "660000000000000000000013", ckTypeId: "System.Identity/IdentityResource" },
    { rtId: "660000000000000000000001", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000002", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000003", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000004", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000005", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000006", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000007", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000008", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000009", ckTypeId: "System.Identity/Role" },
    { rtId: "66000000000000000000000a", ckTypeId: "System.Identity/Role" },
    { rtId: "66000000000000000000000b", ckTypeId: "System.Identity/Role" },
    { rtId: "66000000000000000000000c", ckTypeId: "System.Identity/Role" },
    { rtId: "66000000000000000000000d", ckTypeId: "System.Identity/Role" },
    { rtId: "66000000000000000000000e", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000060", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000061", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000062", ckTypeId: "System.Identity/Role" },
    { rtId: "660000000000000000000063", ckTypeId: "System.Identity/Role" }
];
// [origin rtId, association role, target rtId, target CK type]
const SEED_ASSOCIATIONS = [
    ["660000000000000000000051", "System.Identity/PolicyPermission", "660000000000000000000050", "System.Identity/DataPermission"],
    ["660000000000000000000054", "System.Identity/PolicyPermission", "660000000000000000000052", "System.Identity/DataPermission"],
    ["660000000000000000000055", "System.Identity/PolicyPermission", "660000000000000000000053", "System.Identity/DataPermission"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000001", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000002", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000003", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000004", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000005", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000006", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000007", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000008", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000009", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "66000000000000000000000a", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "66000000000000000000000b", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "66000000000000000000000c", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "66000000000000000000000d", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "66000000000000000000000e", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000061", "System.Identity/Role"],
    ["660000000000000000000040", "System.Identity/AssignedRole", "660000000000000000000062", "System.Identity/Role"],
    ["660000000000000000000002", "System.Identity/GrantsPermission", "660000000000000000000050", "System.Identity/DataPermission"],
    ["660000000000000000000061", "System.Identity/GrantsPermission", "660000000000000000000052", "System.Identity/DataPermission"],
    ["660000000000000000000061", "System.Identity/GrantsPermission", "660000000000000000000053", "System.Identity/DataPermission"],
    ["660000000000000000000062", "System.Identity/GrantsPermission", "660000000000000000000052", "System.Identity/DataPermission"]
];

const clean = s => String(s).split(/[\t\r\n]/).join(" ");
const emit = cols => print("ROW\t" + cols.map(clean).join("\t"));
const hex = id => String(id).toLowerCase();

const systemDb = conn.getSiblingDB(PARAMS.systemDb);
const allTenants = [{ tenantId: PARAMS.systemDb, db: PARAMS.systemDb, parent: null }].concat(
    systemDb.getCollection("RtEntity_SystemTenant")
        .find({}, { "attributes.tenantId": 1, "attributes.databaseName": 1, "attributes.parentTenantId": 1 })
        .toArray()
        .map(t => ({
            tenantId: t.attributes.tenantId,
            db: t.attributes.databaseName || t.attributes.tenantId,
            parent: t.attributes.parentTenantId || PARAMS.systemDb
        })));
const byId = new Map();
allTenants.forEach(t => byId.set(t.tenantId, t));
// Client mirroring provisions a client from any ancestor of a tenant (the parent or a tenant above it), so
// provisionedByParentTenantId is foreign when it names a tenant outside the tenant's ancestor chain.
const ancestorsOf = tenant => {
    const result = [];
    for (let p = tenant.parent; p && result.indexOf(p) < 0; p = byId.has(p) ? byId.get(p).parent : null) result.push(p);
    return result;
};
const selected = PARAMS.tenants.length
    ? PARAMS.tenants.map(id => byId.get(id) || { tenantId: id, db: null, parent: null })
    : allTenants.slice().sort((a, b) => a.tenantId < b.tenantId ? -1 : a.tenantId > b.tenantId ? 1 : 0);
const existing = new Set(conn.getMongo().getDBNames());
const seedIds = SEED_ENTITIES.map(e => ObjectId(e.rtId));

print("SEED\t" + SEED_BLUEPRINT + "\t" + SEED_ENTITIES.length + "\t" + SEED_ASSOCIATIONS.length);
for (const t of selected) {
    if (!t.db || !existing.has(t.db)) {
        emit([t.tenantId, "tenant", "-", "database " + (t.db || "unknown"), "NO-DATABASE"]);
        continue;
    }
    const d = conn.getSiblingDB(t.db);
    // Entities of derived CK types share the collection of their root type, so every entity collection of the tenant
    // is searched for the seed rtIds and each document is judged by its ckTypeId.
    const found = new Map();
    for (const name of d.getCollectionNames().filter(n => n.startsWith("RtEntity_")).sort()) {
        d.getCollection(name)
            .find({ _id: { $in: seedIds } }, { _id: 1, ckTypeId: 1, "attributes.provisionedByParentTenantId": 1 })
            .forEach(doc => {
                const id = hex(doc._id);
                if (!found.has(id)) found.set(id, []);
                found.get(id).push({ collection: name, doc: doc });
            });
    }

    const ancestors = ancestorsOf(t);
    let present = 0;
    const missing = [], unexpected = [];
    for (const e of SEED_ENTITIES) {
        const hits = found.get(e.rtId) || [];
        if (hits.length === 0) {
            missing.push(e.rtId);
            emit([t.tenantId, "entity", e.rtId, e.ckTypeId, "MISSING"]);
            continue;
        }
        present++;
        if (hits.length > 1) {
            unexpected.push(e.rtId);
            emit([t.tenantId, "entity", e.rtId, hits.length + " copies in " + hits.map(h => h.collection).join(","),
                "DUPLICATE"]);
        }
        for (const hit of hits) {
            if (hit.doc.ckTypeId !== e.ckTypeId) {
                unexpected.push(e.rtId);
                emit([t.tenantId, "entity", e.rtId,
                    "ckTypeId " + hit.doc.ckTypeId + " in " + hit.collection + " (expected " + e.ckTypeId + ")",
                    "TYPE-MISMATCH"]);
            }
            const provisionedBy = hit.doc.attributes ? hit.doc.attributes.provisionedByParentTenantId : null;
            if (provisionedBy != null && ancestors.indexOf(provisionedBy) < 0) {
                unexpected.push(e.rtId);
                emit([t.tenantId, "entity", e.rtId,
                    "provisionedByParentTenantId " + provisionedBy + ", ancestors " + (ancestors.join(">") || "none"),
                    "FOREIGN-PROVISIONING"]);
            }
        }
    }

    let assocPresent = 0, assocMissing = 0, assocDuplicate = 0;
    const associations = d.getCollection("RtAssociation");
    for (const a of SEED_ASSOCIATIONS) {
        const count = associations.countDocuments({
            originRtId: ObjectId(a[0]), associationRoleId: a[1], targetRtId: ObjectId(a[2]), targetCkTypeId: a[3]
        });
        const id = a[0] + " -" + a[1] + "-> " + a[2];
        if (count === 0) {
            assocMissing++;
            emit([t.tenantId, "association", id, a[3], "ASSOC-MISSING"]);
        } else {
            assocPresent++;
            if (count > 1) {
                assocDuplicate++;
                emit([t.tenantId, "association", id, count + " copies", "ASSOC-DUPLICATE"]);
            }
        }
    }

    print("SUM\t" + [t.tenantId, present, SEED_ENTITIES.length, missing.join(",") || "-",
        Array.from(new Set(unexpected)).join(",") || "-", assocPresent, SEED_ASSOCIATIONS.length, assocMissing,
        assocDuplicate].map(clean).join("\t"));
}
print("END");
