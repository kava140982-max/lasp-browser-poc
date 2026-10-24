// LASP crypto — ECHT (WebCrypto): ECDSA-P256, SHA-256, AES-GCM/PBKDF2.
// Kein Ed25519 (Browser-Support lückenhaft) — ehrlich: P-256 statt Ed25519 aus Spec-Punkt 5.
(function () {
  const te = new TextEncoder(), td = new TextDecoder();
  const b64u = {
    enc(buf) {
      const b = new Uint8Array(buf);
      let s = "";
      for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
    dec(s) {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };

  async function sha256hex(str) {
    const d = await crypto.subtle.digest("SHA-256", te.encode(str));
    return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
  }

  async function genKeypair() {
    const kp = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const did = "did:lasp:" + b64u.enc(await crypto.subtle.digest("SHA-256", rawPub)).slice(0, 32);
    const jwkPub = await crypto.subtle.exportKey("jwk", kp.publicKey);
    const jwkPriv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    return { did, pubJwk: jwkPub, privJwk: jwkPriv };
  }

  async function importKeys(pubJwk, privJwk) {
    const pub = await crypto.subtle.importKey("jwk", pubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const out = { pub };
    if (privJwk) out.priv = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    return out;
  }

  function canonical(o) {
    if (o === null || typeof o !== "object") return JSON.stringify(o);
    if (Array.isArray(o)) return "[" + o.map(canonical).join(",") + "]";
    return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
  }

  async function sign(privKey, payloadObj) {
    const msg = te.encode(canonical(payloadObj));
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privKey, msg);
    return b64u.enc(sig);
  }

  async function verify(pubKey, payloadObj, sigB64u) {
    try {
      const msg = te.encode(canonical(payloadObj));
      return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, b64u.dec(sigB64u), msg);
    } catch { return false; }
  }

  // --- Envelope / VC (vereinfachtes W3C-VC-Profil, ehrlich gelabelt) ---
  async function issueEnvelope(humanKeys, agentDid, scope, minutesValid = 15) {
    const now = Date.now();
    const env = {
      kind: "lasp/authority-envelope/v1",
      principal: humanKeys.did, agent: agentDid, scope,
      window: { notBefore: new Date(now - 30000).toISOString(), notAfter: new Date(now + minutesValid * 60000).toISOString() },
      killSwitch: true, nonce: b64u.enc(crypto.getRandomValues(new Uint8Array(12))),
    };
    env.signature = await sign(humanKeys.priv, env);
    return env;
  }

  async function verifyEnvelope(env, humanPub) {
    const { signature, ...body } = env;
    if (!signature) return { ok: false, reason: "MISSING_SIGNATURE" };
    const sigOk = await verify(humanPub, body, signature);
    if (!sigOk) return { ok: false, reason: "BAD_SIGNATURE" };
    const t = Date.now();
    if (new Date(env.window.notBefore).getTime() > t) return { ok: false, reason: "NOT_YET_VALID" };
    if (new Date(env.window.notAfter).getTime() < t) return { ok: false, reason: "EXPIRED" };
    return { ok: true };
  }

  async function issueVC(issuerKeys, subjectDid, capability, scope, minutesValid = 15) {
    const now = Date.now();
    const vc = {
      kind: "lasp/vc/v1", issuer: issuerKeys.did, subject: subjectDid,
      capability, scope, exp: new Date(now + minutesValid * 60000).toISOString(),
      nonce: b64u.enc(crypto.getRandomValues(new Uint8Array(9))),
    };
    vc.signature = await sign(issuerKeys.priv, vc);
    return vc;
  }

  async function verifyVC(vc, issuerPub) {
    const { signature, ...body } = vc;
    if (!signature) return { ok: false, reason: "MISSING_SIGNATURE" };
    if (!(await verify(issuerPub, body, signature))) return { ok: false, reason: "BAD_SIGNATURE" };
    if (new Date(vc.exp).getTime() < Date.now()) return { ok: false, reason: "EXPIRED" };
    return { ok: true };
  }

  // --- Audit-Verschlüsselung (AES-GCM, PBKDF2 100k) ---
  async function deriveKey(password, saltB64u) {
    if (typeof password !== "string" || password.length < 12) { const e = new Error("PASSWORD_TOO_WEAK"); e.code = "PASSWORD_TOO_WEAK"; throw e; }
    const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: b64u.dec(saltB64u), iterations: 100000, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function encryptLog(password, plainText) {
    if (typeof password !== "string" || password.length < 12) { const e = new Error("PASSWORD_TOO_WEAK"); e.code = "PASSWORD_TOO_WEAK"; throw e; }
    const salt = b64u.enc(crypto.getRandomValues(new Uint8Array(16)));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(plainText));
    return JSON.stringify({ alg: "PBKDF2-100k/AES-GCM-256", salt, iv: b64u.enc(iv), data: b64u.enc(ct) });
  }
  async function decryptLog(password, bundle) {
    const o = JSON.parse(bundle);
    const key = await deriveKey(password, o.salt);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64u.dec(o.iv) }, key, b64u.dec(o.data));
    return td.decode(pt);
  }

  window.LASPCrypto = {
    b64u, sha256hex, genKeypair, importKeys, canonical, sign, verify,
    issueEnvelope, verifyEnvelope, issueVC, verifyVC, encryptLog, decryptLog,
  };
})();
