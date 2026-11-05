// identity-secret-management-role-check.snapshot.js -- READ-ONLY identity snapshot (AB#8155).
//
// Run by identity-secret-management-role-check.sh inside mongosh before and after the inventory; both snapshots must
// be equal, otherwise something created or changed identities while the inventory ran (the earlier octo-cli version
// created xt_ shadow users through its token exchange). Expects the global `conn`. Read operations only.
//
// Covers every tenant database (not only the selected tenants): a side effect could hit any of them.
// Output: one line "SNAP <json>" with, per database, counts of users, xt_ users and external tenant user mappings and
// the newest change timestamp of users and mappings.

const snapSystemDb = conn.getSiblingDB("octosystem");
const snapDbNames = ["octosystem"].concat(
    snapSystemDb.getCollection("RtEntity_SystemTenant")
        .find({}, { "attributes.tenantId": 1, "attributes.databaseName": 1 })
        .toArray()
        .map(t => t.attributes.databaseName || t.attributes.tenantId))
    .sort();
const snapExisting = new Set(conn.getMongo().getDBNames());
const snapNewest = coll => {
    const newest = coll.find({}, { rtChangedDateTime: 1 }).sort({ rtChangedDateTime: -1 }).limit(1).toArray();
    return newest.length && newest[0].rtChangedDateTime != null ? String(newest[0].rtChangedDateTime) : "";
};
const snapshot = {};
for (const name of snapDbNames) {
    if (!snapExisting.has(name)) { snapshot[name] = "no-database"; continue; }
    const d = conn.getSiblingDB(name);
    const users = d.getCollection("RtEntity_SystemIdentityUser");
    const mappings = d.getCollection("RtEntity_SystemIdentityExternalTenantUserMapping");
    snapshot[name] = {
        users: users.countDocuments({}),
        xtUsers: users.countDocuments({ "attributes.userName": { $regex: "^xt_" } }),
        mappings: mappings.countDocuments({}),
        newestUser: snapNewest(users),
        newestMapping: snapNewest(mappings)
    };
}
print("SNAP " + JSON.stringify(snapshot));
