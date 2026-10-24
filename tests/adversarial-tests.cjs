const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

function loadLASP() {
  const context = {
    console,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    WebAssembly,
  };
  context.window = context;
  context.document = { modelContext: undefined, querySelectorAll: () => [] };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync("src/lasp-crypto.js", "utf8"), context, { filename: "src/lasp-crypto.js" });
  vm.runInContext(fs.readFileSync("src/lasp-core.js", "utf8"), context, { filename: "src/lasp-core.js" });
  return { C: context.LASPCrypto, L: context.LASP };
}

function validRequest(contextPayload = "normale Analyse") {
  return {
    schema: "lasp/request/v1",
    case_id: "adversarial-test",
    module_id: "lasp-proxy",
    task: "assess",
    data_class: "public_research",
    model_route: "local",
    tenant_id: "sandbox-tenant-1",
    authorization_id: "lasp-authz-demo-001",
    authorization_verified: true,
    role: "analyst",
    context_payload: contextPayload,
    environment_integrity: true,
  };
}

async function makeKeys(C) {
  const material = await C.genKeypair();
  const keys = await C.importKeys(material.pubJwk, material.privJwk);
  keys.did = material.did;
  return { material, keys };
}

async function makeCapability(C, keys, overrides = {}) {
  const cap = {
    kind: "lasp/cap/v1",
    tool: "audit-seal",
    hostAllow: ["localhost"],
    pathAllow: ["/audit/seal"],
    envAllow: [],
    exp: new Date(Date.now() + 60_000).toISOString(),
    nonce: "test-capability",
    issuer: keys.did,
    ...overrides,
  };
  cap.signature = await C.sign(keys.priv, cap);
  return cap;
}

function sandboxIO(path = "/audit/seal") {
  return { tool: "audit-seal", host: "localhost", path, env: {}, a: 0, b: 0 };
}

test("ADV-01: Zero-width injection is denied", () => {
  const { L } = loadLASP();
  const result = L.evaluate({ ...validRequest("A\u200BB"), inject_blocked: true });
  assert.equal(result.status, "denied");
  assert.ok(result.flags.includes("INVISIBLE_UNICODE_BLOCKED"));
});

test("ADV-02: capability scope denies the wrong path", async () => {
  const { C, L } = loadLASP();
  const { keys } = await makeKeys(C);
  const cap = await makeCapability(C, keys);
  const result = await L.execInSandbox(cap, null, keys.pub, sandboxIO("/audit/delete"));
  assert.equal(result.reason, "CAP_PATH_DENIED");
  assert.equal(L.auditLog.at(-1).type, "PIPELINE_CAPABILITY_DENIED");
});

test("ADV-03: revoked capability is denied", async () => {
  const { C, L } = loadLASP();
  const { keys } = await makeKeys(C);
  const cap = await makeCapability(C, keys, { nonce: "revoked-capability" });
  L.revokedCaps.add(cap.nonce);
  assert.equal(L.checkCapability(cap, sandboxIO()), "CAP_REVOKED");
});

test("ADV-04: audit tampering breaks chain verification", async () => {
  const { L } = loadLASP();
  L.audit("TAMPER_TEST", { value: 1 });
  await L.finalizeChain();
  L.auditLog[0].detail.value = 2;
  const result = await L.verifyChain();
  assert.equal(result.ok, false);
  assert.equal(result.at, 0);
});

test("ADV-05: weak seal password aborts before sealing", async () => {
  const { C, L } = loadLASP();
  const { keys } = await makeKeys(C);
  const cap = await makeCapability(C, keys);
  await assert.rejects(
    L.sealPipeline("too-short", cap, keys.pub),
    (error) => error.code === "PIPELINE_SEAL_ABORTED",
  );
  assert.equal(L.auditLog[0].type, "PIPELINE_SEAL_ABORTED");
});

test("ADV-06: foreign issuer signature is denied", async () => {
  const { C, L } = loadLASP();
  const issuer = await makeKeys(C);
  const foreign = await makeKeys(C);
  const cap = await makeCapability(C, foreign.keys, { issuer: issuer.keys.did });
  const result = await L.execInSandbox(cap, null, issuer.keys.pub, sandboxIO());
  assert.equal(result.reason, "CAP_BAD_SIGNATURE");
});

test("positive: valid HITL signature is accepted", async () => {
  const { C, L } = loadLASP();
  const { keys } = await makeKeys(C);
  const escalation = await L.escalate(keys, "TEST", { action: "review" });
  const result = await L.approve(keys, escalation.nonce);
  assert.equal(result.ok, true);
  assert.equal(L.hitlQueue[0].approved, true);
});

test("positive: valid Wasm-gated seal encrypts an intact chain", async () => {
  const { C, L } = loadLASP();
  const { keys } = await makeKeys(C);
  const cap = await makeCapability(C, keys);
  const result = await L.sealPipeline("correct-horse-battery", cap, keys.pub);
  assert.equal(result.ok, true);
  assert.equal(result.chain.ok, true);
  const plaintext = await C.decryptLog("correct-horse-battery", result.bundle);
  assert.match(plaintext, /PIPELINE_SEAL_APPROVED/);
});

test("positive: short passwords are rejected by crypto export", async () => {
  const { C } = loadLASP();
  await assert.rejects(C.encryptLog("short", "audit"), (error) => error.code === "PASSWORD_TOO_WEAK");
});
