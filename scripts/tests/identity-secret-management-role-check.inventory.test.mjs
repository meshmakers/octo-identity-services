// Tests for identity-secret-management-role-check.{inventory,snapshot}.js (AB#8155) against an in-memory MongoDB mock.
// Run: node scripts/tests/identity-secret-management-role-check.inventory.test.mjs   (no dependencies)
//
// The mock exposes read methods only (find/toArray/forEach/sort/limit/countDocuments/getDBNames); any other member
// access fails the test, so a write call in the scripts cannot pass. It also applies the projections and fails when a
// query has none or when a document with secret material (passwordHash, securityStamp, clientSecrets) is returned.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const INVENTORY = readFileSync(join(here, "..", "identity-secret-management-role-check.inventory.js"), "utf8");
const SNAPSHOT = readFileSync(join(here, "..", "identity-secret-management-role-check.snapshot.js"), "utf8");

const SM = "660000000000000000000060", TM = "6600000000000000000000a1", UM = "6600000000000000000000a2", OTHER = "6600000000000000000000a3";
const SECRET_FIELDS = ["passwordHash", "securityStamp", "clientSecrets"];
const secrets = { passwordHash: "HASH", securityStamp: "STAMP", clientSecrets: [{ value: "S" }] };
const roles = [
    { _id: SM, attributes: { name: "SecretManagement" } },
    { _id: TM, attributes: { name: "TenantManagement" } },
    { _id: UM, attributes: { name: "UserManagement" } },
    { _id: OTHER, attributes: { name: "AdminPanelManagement" } }
];
const assoc = (origin, roleId, target) => ({ _id: origin + roleId + target, originRtId: origin, targetRtId: target, associationRoleId: roleId });
const AR = "System.Identity/AssignedRole", GM = "System.Identity/GroupMember", CG = "System.Identity/ChildGroup";

const data = {
    octosystem: {
        RtEntity_SystemTenant: [
            { _id: "t1", attributes: { tenantId: "tenanta", databaseName: "tenanta" } },
            { _id: "t2", attributes: { tenantId: "tenantb" } },
            { _id: "t3", attributes: { tenantId: "tenantc", databaseName: "missing" } }
        ],
        RtEntity_SystemIdentityRole: roles,
        RtEntity_SystemIdentityGroup: [],
        RtEntity_SystemIdentityUser: [{ _id: "root", rtChangedDateTime: "2026-11-01", attributes: { userName: "root", ...secrets } }],
        RtEntity_SystemIdentityClient: [],
        RtEntity_SystemIdentityExternalTenantUserMapping: [],
        RtAssociation: [assoc("root", AR, SM)]
    },
    tenanta: {
        RtEntity_SystemIdentityRole: roles,
        RtEntity_SystemIdentityGroup: [{ _id: "g1", attributes: { groupName: "Admins" } }, { _id: "g2", attributes: { groupName: "Secrets" } }],
        RtEntity_SystemIdentityUser: [
            { _id: "u1", rtChangedDateTime: "2026-11-02", attributes: { userName: "admin@example.com", ...secrets } },
            { _id: "u2", rtChangedDateTime: "2026-11-04", attributes: { userName: "xt_abc", ...secrets } },
            { _id: "u3", rtChangedDateTime: "2026-11-03", attributes: { userName: "bob", ...secrets } },
            { _id: "u4", rtChangedDateTime: "2026-11-01", attributes: { userName: "plain", ...secrets } },
            { _id: "u5", rtChangedDateTime: "2026-11-01", attributes: { userName: "tm\tuser", ...secrets } }
        ],
        RtEntity_SystemIdentityClient: [{ _id: "c1", attributes: { clientId: "svc", ...secrets } }],
        RtEntity_SystemIdentityExternalTenantUserMapping: [
            { _id: "m1", rtChangedDateTime: "2026-11-02", attributes: { sourceTenantId: "octosystem", sourceUserName: "x@y.z", mappedRoleIds: [TM] } },
            { _id: "m2", rtChangedDateTime: "2026-11-01", attributes: { sourceTenantId: "octosystem", sourceUserName: "ops", mappedRoleIds: [] } }
        ],
        RtAssociation: [
            assoc("u1", AR, SM),                       // direct holder
            assoc("g1", GM, "u2"), assoc("g1", AR, TM), // u2 via group g1 (TenantManagement) ...
            assoc("g1", CG, "g2"), assoc("g2", AR, SM), // ... whose child group g2 grants SecretManagement
            assoc("u3", AR, UM),                       // loses
            assoc("u4", AR, OTHER),                    // neither: not listed
            assoc("u5", AR, TM),                       // loses, name with a tab
            assoc("c1", AR, TM),                       // client loses
            assoc("g2", GM, "m2"),                     // mapping holds via group g2
            assoc("g2", CG, "g1"),                     // a child-group cycle must not hang
            { _id: "other", originRtId: "u3", targetRtId: "x", associationRoleId: "Some/Other" }
        ]
    },
    tenantb: {
        RtEntity_SystemIdentityRole: roles.filter(r => r._id !== SM),
        RtEntity_SystemIdentityUser: [{ _id: "b1", attributes: { userName: "b", ...secrets } }],
        RtEntity_SystemIdentityExternalTenantUserMapping: []
    }
};

const getPath = (doc, path) => path.split(".").reduce((v, k) => (v == null ? undefined : v[k]), doc);
const matches = (doc, filter) => Object.entries(filter).every(([path, cond]) => {
    const v = getPath(doc, path);
    if (cond && typeof cond === "object" && "$in" in cond) return cond.$in.includes(v);
    if (cond && typeof cond === "object" && "$regex" in cond) return typeof v === "string" && new RegExp(cond.$regex).test(v);
    return v === cond;
});
const project = (doc, proj) => {
    const out = { _id: doc._id };
    for (const path of Object.keys(proj)) {
        const v = getPath(doc, path);
        if (v === undefined || path === "_id") continue;
        const keys = path.split(".");
        let o = out;
        keys.slice(0, -1).forEach(k => { o = o[k] = o[k] || {}; });
        o[keys[keys.length - 1]] = v;
    }
    return out;
};
const strict = (name, obj) => new Proxy(obj, {
    get(target, prop) {
        if (typeof prop === "symbol" || prop in target) return target[prop];
        throw new Error(`${name}.${String(prop)} is not a read operation allowed by the mock`);
    }
});

function makeConn(log) {
    const cursor = docs => strict("cursor", {
        toArray: () => docs.slice(),
        forEach: fn => docs.forEach(fn),
        sort: spec => { const [[k, dir]] = Object.entries(spec); return cursor(docs.slice().sort((a, b) => (getPath(a, k) < getPath(b, k) ? -dir : getPath(a, k) > getPath(b, k) ? dir : 0))); },
        limit: n => cursor(docs.slice(0, n))
    });
    const collection = (db, name) => strict("collection", {
        find(filter, proj) {
            assert.ok(proj && Object.keys(proj).length > 0, `find on ${db}.${name} without projection`);
            for (const f of SECRET_FIELDS) assert.ok(!Object.keys(proj).some(k => k.endsWith(f)), `projection on ${db}.${name} selects ${f}`);
            log.push(`${db}.${name}.find`);
            const docs = ((data[db] || {})[name] || []).filter(d => matches(d, filter)).map(d => project(d, proj));
            for (const d of docs) for (const f of SECRET_FIELDS) assert.ok(!JSON.stringify(d).includes(f), `${db}.${name} returned ${f}`);
            return cursor(docs);
        },
        countDocuments(filter) { log.push(`${db}.${name}.countDocuments`); return ((data[db] || {})[name] || []).filter(d => matches(d, filter)).length; }
    });
    const database = name => strict("db", { getCollection: c => collection(name, c), getMongo: () => mongo });
    const mongo = strict("mongo", { getDBNames: () => Object.keys(data) });
    return strict("conn", { getSiblingDB: database, getMongo: () => mongo });
}

function run(code, params) {
    const lines = [], log = [];
    vm.runInNewContext(code, { conn: makeConn(log), PARAMS: params, print: s => lines.push(String(s)) });
    return { lines, log };
}
const rows = lines => lines.filter(l => l.startsWith("ROW\t")).map(l => l.slice(4));

let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log(`ok - ${name}`); };

test("inventory classifies direct, group, child-group, client and mapping subjects", () => {
    const { lines } = run(INVENTORY, { tenants: [], withEmail: false, idsOnly: false });
    assert.equal(lines[lines.length - 1], "END");
    assert.deepEqual(rows(lines), [
        "octosystem\tuser\troot\troot\tyes\tno\tHOLDS",
        "tenanta\tuser\tu1\tadm***@example.com\tyes\tno\tHOLDS",
        "tenanta\tuser\tu2\txt_abc\tyes\tyes\tHOLDS",
        "tenanta\tuser\tu3\tbob\tno\tyes\tLOSES",
        "tenanta\tuser\tu5\ttm user\tno\tyes\tLOSES",
        "tenanta\tclient\tc1\tsvc\tno\tyes\tLOSES",
        "tenanta\tmapping\tm1\toctosystem/x@y***@y.z\tno\tyes\tLOSES",
        "tenanta\tmapping\tm2\toctosystem/ops\tyes\tyes\tHOLDS", // g2 -> child g1 (cycle) adds TenantManagement
        "tenantb\ttenant\t-\t-\t-\t-\tNO-ROLE",
        "tenantc\ttenant\t-\t-\t-\t-\tERROR"
    ]);
});

test("--with-email shows e-mail user names unmasked, --ids-only hides names", () => {
    const withEmail = rows(run(INVENTORY, { tenants: ["tenanta"], withEmail: true, idsOnly: false }).lines);
    assert.ok(withEmail.includes("tenanta\tuser\tu1\tadmin@example.com\tyes\tno\tHOLDS"));
    const idsOnly = rows(run(INVENTORY, { tenants: ["tenanta"], withEmail: false, idsOnly: true }).lines);
    assert.ok(idsOnly.every(r => r.split("\t")[3] === "-"));
    assert.equal(idsOnly.length, 7);
});

test("tenant filter keeps the given order and reports unknown tenants as ERROR", () => {
    assert.deepEqual(rows(run(INVENTORY, { tenants: ["tenantb", "nope"], withEmail: false, idsOnly: false }).lines), [
        "tenantb\ttenant\t-\t-\t-\t-\tNO-ROLE",
        "nope\ttenant\t-\t-\t-\t-\tERROR"
    ]);
});

test("inventory uses read operations with projections only", () => {
    const { log } = run(INVENTORY, { tenants: [], withEmail: false, idsOnly: false });
    assert.ok(log.length > 0 && log.every(l => /\.(find|countDocuments)$/.test(l)), log.join(","));
});

test("snapshot counts users, xt_ users and mappings and the newest change per tenant database", () => {
    const { lines } = run(SNAPSHOT, {});
    assert.equal(lines.length, 1);
    assert.ok(lines[0].startsWith("SNAP "));
    const snap = JSON.parse(lines[0].slice(5));
    assert.deepEqual(Object.keys(snap), ["missing", "octosystem", "tenanta", "tenantb"]);
    assert.equal(snap.missing, "no-database");
    assert.deepEqual(snap.tenanta, { users: 5, xtUsers: 1, mappings: 2, newestUser: "2026-11-04T00:00:00.000Z", newestMapping: "2026-11-02T00:00:00.000Z" });
    assert.deepEqual(snap.tenantb, { users: 1, xtUsers: 0, mappings: 0, newestUser: "", newestMapping: "" });
});

test("snapshot changes when an xt_ shadow user appears (what the old octo-cli version caused)", () => {
    const before = run(SNAPSHOT, {}).lines[0];
    data.tenanta.RtEntity_SystemIdentityUser.push({ _id: "u9", rtChangedDateTime: "2026-11-05", attributes: { userName: "xt_new" } });
    const after = run(SNAPSHOT, {}).lines[0];
    data.tenanta.RtEntity_SystemIdentityUser.pop();
    assert.notEqual(before, after);
});

test("the mock rejects a write call", () => {
    assert.throws(() => run('conn.getSiblingDB("x").getCollection("y").insertOne({});', {}), /insertOne is not a read operation/);
});

console.log(`${passed} passed`);
