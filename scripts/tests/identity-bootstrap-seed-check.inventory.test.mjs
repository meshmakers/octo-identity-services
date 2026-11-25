// Tests for identity-bootstrap-seed-check.inventory.js against an in-memory MongoDB mock.
// Run: node scripts/tests/identity-bootstrap-seed-check.inventory.test.mjs   (no dependencies)
//
// The mock exposes read methods only (find/toArray/forEach/countDocuments/getCollectionNames/getDBNames); any other
// member access fails the test, so a write call in the script cannot pass. find() must carry a projection, and a
// projection that selects client secrets fails the test.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const INVENTORY = readFileSync(join(here, "..", "identity-bootstrap-seed-check.inventory.js"), "utf8");

// The expected seed, taken from the script itself (the manifest test in IdentityServerPersistence.UnitTests pins it
// to the seed files).
const manifestCode = INVENTORY.slice(INVENTORY.indexOf("const SEED_ENTITIES"), INVENTORY.indexOf("const clean"));
const { SEED_ENTITIES, SEED_ASSOCIATIONS } = vm.runInNewContext(
    manifestCode + "\n({ SEED_ENTITIES: SEED_ENTITIES, SEED_ASSOCIATIONS: SEED_ASSOCIATIONS })");
assert.equal(SEED_ENTITIES.length, 41);
assert.equal(SEED_ASSOCIATIONS.length, 23);

const ROOT_COLLECTION = {
    "System.Identity/ApiResource": "RtEntity_SystemIdentityResource",
    "System.Identity/ApiScope": "RtEntity_SystemIdentityResource",
    "System.Identity/IdentityResource": "RtEntity_SystemIdentityResource"
};
const collectionOf = ck => ROOT_COLLECTION[ck] || "RtEntity_" + ck.split(".").join("").split("/").join("");

// A complete tenant database: every seed entity once (derived types in their root collection) and every association.
function tenantDb(provisionedBy) {
    const db = { RtAssociation: [], RtEntity_SystemIdentityUser: [{ _id: "u1", ckTypeId: "System.Identity/User" }] };
    for (const e of SEED_ENTITIES) {
        const doc = { _id: e.rtId, ckTypeId: e.ckTypeId, attributes: { clientSecrets: [{ value: "S" }] } };
        if (e.ckTypeId === "System.Identity/Client" && provisionedBy) doc.attributes.provisionedByParentTenantId = provisionedBy;
        (db[collectionOf(e.ckTypeId)] = db[collectionOf(e.ckTypeId)] || []).push(doc);
    }
    SEED_ASSOCIATIONS.forEach((a, i) => db.RtAssociation.push(
        { _id: "a" + i, originRtId: a[0], associationRoleId: a[1], targetRtId: a[2], targetCkTypeId: a[3] }));
    return db;
}

const CLIENT = SEED_ENTITIES.find(e => e.ckTypeId === "System.Identity/Client").rtId;
const ROLE = SEED_ENTITIES.find(e => e.ckTypeId === "System.Identity/Role").rtId;
const SCOPE = SEED_ENTITIES.find(e => e.ckTypeId === "System.Identity/ApiScope").rtId;
const A0 = SEED_ASSOCIATIONS[0], A1 = SEED_ASSOCIATIONS[1], A2 = SEED_ASSOCIATIONS[2];

function makeData() {
    const data = {
        octosystem: tenantDb(null),
        clean: tenantDb("octosystem"),
        grandchild: tenantDb("octosystem"), // mirrored from an ancestor above the parent: fine
        broken: tenantDb("octosystem")
    };
    data.octosystem.RtEntity_SystemTenant = [
        { _id: "t1", attributes: { tenantId: "clean", databaseName: "clean", parentTenantId: "octosystem" } },
        { _id: "t2", attributes: { tenantId: "grandchild", parentTenantId: "clean" } },
        { _id: "t3", attributes: { tenantId: "broken", databaseName: "broken", parentTenantId: "octosystem" } },
        { _id: "t4", attributes: { tenantId: "gone", databaseName: "gone", parentTenantId: "octosystem" } }
    ];
    const b = data.broken;
    b.RtEntity_SystemIdentityRole = b.RtEntity_SystemIdentityRole.filter(d => d._id !== ROLE);          // MISSING
    b.RtEntity_SystemIdentityResource.find(d => d._id === SCOPE).ckTypeId = "System.Identity/ApiResource"; // TYPE-MISMATCH
    b.RtEntity_SystemIdentityClient.find(d => d._id === CLIENT).attributes.provisionedByParentTenantId = "clean"; // FOREIGN
    b.RtEntity_SystemIdentityGroup.push({ _id: CLIENT, ckTypeId: "System.Identity/Client", attributes: {} });   // DUPLICATE
    b.RtAssociation = b.RtAssociation.filter(a => !(a.originRtId === A0[0] && a.targetRtId === A0[2]));     // ASSOC-MISSING
    b.RtAssociation.push({ _id: "dup", originRtId: A1[0], associationRoleId: A1[1], targetRtId: A1[2], targetCkTypeId: A1[3] }); // ASSOC-DUPLICATE
    b.RtAssociation.find(a => a.originRtId === A2[0] && a.targetRtId === A2[2]).targetCkTypeId = "System.Identity/Role"; // wrong target type: missing
    return data;
}

const getPath = (doc, path) => path.split(".").reduce((v, k) => (v == null ? undefined : v[k]), doc);
const matches = (doc, filter) => Object.entries(filter).every(([path, cond]) => {
    const v = getPath(doc, path);
    if (cond && typeof cond === "object" && "$in" in cond) return cond.$in.includes(v);
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

function makeConn(data, log) {
    const cursor = docs => strict("cursor", { toArray: () => docs.slice(), forEach: fn => docs.forEach(fn) });
    const collection = (db, name) => strict("collection", {
        find(filter, proj) {
            assert.ok(proj && Object.keys(proj).length > 0, `find on ${db}.${name} without projection`);
            assert.ok(!Object.keys(proj).some(k => k.includes("clientSecrets")), `projection on ${db}.${name} selects secrets`);
            log.push(`${db}.${name}.find`);
            const docs = ((data[db] || {})[name] || []).filter(d => matches(d, filter)).map(d => project(d, proj));
            for (const d of docs) assert.ok(!JSON.stringify(d).includes("clientSecrets"), `${db}.${name} returned secrets`);
            return cursor(docs);
        },
        countDocuments(filter) {
            log.push(`${db}.${name}.countDocuments`);
            return ((data[db] || {})[name] || []).filter(d => matches(d, filter)).length;
        }
    });
    const database = name => strict("db", {
        getCollection: c => collection(name, c),
        getCollectionNames: () => Object.keys(data[name] || {}),
        getMongo: () => mongo
    });
    const mongo = strict("mongo", { getDBNames: () => Object.keys(data) });
    return strict("conn", { getSiblingDB: database, getMongo: () => mongo });
}

function run(params, data = makeData()) {
    const lines = [], log = [];
    vm.runInNewContext(INVENTORY, {
        conn: makeConn(data, log), PARAMS: params, print: s => lines.push(String(s)), ObjectId: hex => String(hex).toLowerCase()
    });
    return { lines, log };
}
const rows = lines => lines.filter(l => l.startsWith("ROW\t")).map(l => l.slice(4));
const sums = lines => lines.filter(l => l.startsWith("SUM\t")).map(l => l.slice(4));

let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log(`ok - ${name}`); };

test("a tenant holding the complete seed has no finding, also a grandchild with clients mirrored from above", () => {
    const { lines } = run({ systemDb: "octosystem", tenants: ["octosystem", "clean", "grandchild"] });
    assert.equal(lines[0], "SEED\tSystem.Identity.Bootstrap-1.10.0\t41\t23");
    assert.equal(lines[lines.length - 1], "END");
    assert.deepEqual(rows(lines), []);
    assert.deepEqual(sums(lines), [
        "octosystem\t41\t41\t-\t-\t23\t23\t0\t0",
        "clean\t41\t41\t-\t-\t23\t23\t0\t0",
        "grandchild\t41\t41\t-\t-\t23\t23\t0\t0"
    ]);
});

test("missing, duplicate, wrong-type and foreign entities and missing or duplicate associations are reported", () => {
    const { lines } = run({ systemDb: "octosystem", tenants: ["broken"] });
    const classes = rows(lines).map(r => r.split("\t")).map(c => `${c[2]} ${c[4]}`);
    assert.deepEqual(classes.sort(), [
        `${A0[0]} -${A0[1]}-> ${A0[2]} ASSOC-MISSING`,
        `${A1[0]} -${A1[1]}-> ${A1[2]} ASSOC-DUPLICATE`,
        `${A2[0]} -${A2[1]}-> ${A2[2]} ASSOC-MISSING`,
        `${CLIENT} DUPLICATE`,
        `${CLIENT} FOREIGN-PROVISIONING`,
        `${ROLE} MISSING`,
        `${SCOPE} TYPE-MISMATCH`
    ].sort());
    const sum = sums(lines)[0].split("\t");
    assert.deepEqual(sum.slice(0, 4), ["broken", "40", "41", ROLE]);
    assert.deepEqual(sum[4].split(",").sort(), [CLIENT, SCOPE].sort());
    assert.deepEqual(sum.slice(5), ["21", "23", "2", "1"]);
});

test("every tenant of the system database is checked by default, a tenant without database is NO-DATABASE", () => {
    const { lines } = run({ systemDb: "octosystem", tenants: [] });
    assert.deepEqual(sums(lines).map(s => s.split("\t")[0]), ["broken", "clean", "grandchild", "octosystem"]);
    assert.ok(rows(lines).includes("gone\ttenant\t-\tdatabase gone\tNO-DATABASE"));
});

test("an unknown tenant is NO-DATABASE", () => {
    assert.deepEqual(rows(run({ systemDb: "octosystem", tenants: ["nope"] }).lines),
        ["nope\ttenant\t-\tdatabase unknown\tNO-DATABASE"]);
});

test("the check uses read operations with projections only", () => {
    const { log } = run({ systemDb: "octosystem", tenants: [] });
    assert.ok(log.length > 0 && log.every(l => /\.(find|countDocuments)$/.test(l)), log.join(","));
});

test("the mock rejects a write call", () => {
    assert.throws(() => vm.runInNewContext('conn.getSiblingDB("x").getCollection("y").insertOne({});',
        { conn: makeConn(makeData(), []) }), /insertOne is not a read operation/);
});

console.log(`${passed} passed`);
