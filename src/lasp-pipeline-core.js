// LASP Pipeline Core — Stufe-1-Iteration (B → A → C), browserkompatibel (WebCrypto).
// Integriert in das bestehende PoC: nutzt window.LASPCrypto (echte WebCrypto-Primitive)
// und den echten Audit-Logger aus lasp-core.js (SHA-256-Hashkette, see finalizeChain/verifyChain).
// SIMULATED_LAB / not_a_certification.
(function () {
  "use strict";

  const GENESIS_HASH = "0".repeat(64);

  // Kryptografie: bevorzugt das echte LASPCrypto-Modul (WebCrypto), mit eigenem Fallback.
  function _crypto() {
    if (typeof window !== "undefined" && window.LASPCrypto) return window.LASPCrypto;
    return null;
  }

  const _textToBuffer = (text) => new TextEncoder().encode(text);
  const _bufferToHex = (buffer) =>
    Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");

  async function _sha256(message) {
    const C = _crypto();
    if (C) return C.sha256hex(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", _textToBuffer(message));
    return _bufferToHex(hashBuffer);
  }

  // Signatur-Verifikation: base64 (Standard-Arbeitskopie) ODER base64url (PoC-Konvention aus lasp-crypto.js).
  async function _verifySignature(pubKey, dataBuffer, signatureString) {
    let sigBuf;
    try {
      const s = signatureString.replace(/-/g, "+").replace(/_/g, "/");
      sigBuf = Uint8Array.from(atob(s.padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    } catch {
      throw new Error("HITL_SIGNATURE_MALFORMED");
    }
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, sigBuf, dataBuffer);
  }

  // =============================================================================
  // STUFE B: 9-Stufen-Evaluator (Fokus: Inject / DOM Sanitization)
  // =============================================================================
  async function evaluateInjectStage(rawInput) {
    const findings = [];
    let sanitized = String(rawInput ?? "");
    let isBlocked = false;

    // 1. Unsichtbare Unicode-Zeichen (Zero-Width Space etc.)
    if (/[\u200B-\u200D\uFEFF]/.test(sanitized)) {
      findings.push("INVISIBLE_UNICODE_DETECTED");
      sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF]/g, "");
      isBlocked = true; // Fail-closed
    }

    // 2. Missbräuchliche ARIA / Hidden Marker (Simuliert)
    if (sanitized.includes('aria-hidden="true"') || sanitized.includes("display:none")) {
      findings.push("SUSPICIOUS_DOM_MARKER");
      isBlocked = true;
    }

    // 3. Integration mit dem echten Evaluator aus lasp-core.js (falls geladen):
    //    Mehrsprachige Injektions-Marker + verbotene Intents werden hier NICHT dupliziert,
    //    sondern durch die bestehende SAFE-01/INJECT-Gate abgedeckt.
    if (typeof window !== "undefined" && window.LASP && typeof window.LASP.evaluate === "function") {
      const markerHit = Object.values(window.LASP.INJECTION_MARKERS || {})
        .flat()
        .some((m) => sanitized.toLowerCase().includes(String(m).toLowerCase()));
      if (markerHit) {
        findings.push("INJECTION_MARKER_HIT");
        isBlocked = true;
      }
    }

    const auditPayload = {
      stage: "Inject",
      timestamp: Date.now(),
      findings,
      isBlocked,
      inputHash: await _sha256(String(rawInput ?? "")),
    };

    const newHead = await _appendToAuditChain("EVALUATE_INJECT", auditPayload);

    return { sanitized, isBlocked, findings, auditHash: newHead };
  }

  // =============================================================================
  // STUFE A: HITL Signature Enforcement (Fail-Closed)
  // =============================================================================
  async function enforceHITLApproval(actionPayload, signatureBase64, publicKeyJwk) {
    try {
      if (!signatureBase64 || typeof signatureBase64 !== "string") {
        throw new Error("HITL_SIGNATURE_MISSING");
      }
      if (!publicKeyJwk || typeof publicKeyJwk !== "object") {
        throw new Error("HITL_PUBKEY_MISSING");
      }

      // 1. Schlüssel importieren (ECDSA P-256)
      const cryptoKey = await crypto.subtle.importKey(
        "jwk",
        publicKeyJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );

      // 2. Daten vorbereiten — kanonisch, wenn LASPCrypto verfügbar (wie im Rest des PoCs),
      //    sonst JSON.stringify (Arbeitskopien-Semantik).
      const C = _crypto();
      const canonicalize = C ? C.canonical : (o) => JSON.stringify(o);
      const dataBuffer = _textToBuffer(canonicalize(actionPayload));

      // 3. Verifikation erzwingen
      const isValid = await _verifySignature(cryptoKey, dataBuffer, signatureBase64);
      if (!isValid) throw new Error("HITL_SIGNATURE_INVALID");

      // 4. Audit-Log für erfolgreiche Autorisierung
      const newHead = await _appendToAuditChain("HITL_APPROVED", {
        stage: "HITL_Enforcement",
        timestamp: Date.now(),
        action: actionPayload && actionPayload.action,
        verified: true,
      });

      return { success: true, auditHash: newHead };
    } catch (error) {
      // FAIL-CLOSED: bei jeglichem Fehler hart blockieren, aber trotzdem protokollieren.
      await _appendToAuditChain("HITL_REJECTED", {
        stage: "HITL_Enforcement",
        timestamp: Date.now(),
        error: error.message,
        verified: false,
      });
      return { success: false, error: error.message };
    }
  }

  // =============================================================================
  // STUFE C: Audit Chain Integrity (SHA-256 Hash Chain)
  // =============================================================================
  // Interner Head der Pipeline-Kette (Genesis = 64×'0').
  let _auditChainHead = GENESIS_HASH;

  async function _appendToAuditChain(eventType, payload) {
    const chainLink = { prevHash: _auditChainHead, eventType, payload };
    // Hash über die gesamte Struktur inkl. vorherigem Hash.
    const C = _crypto();
    const serialized = C ? C.canonical(chainLink) : JSON.stringify(chainLink);
    _auditChainHead = await _sha256(serialized);

    // Parallel dazu in den echten, prüfbaren Session-Audit-Log von lasp-core.js spiegeln
    // (append-only, finalizeChain/verifyChain bleiben die maßgebliche Integritätsprüfung).
    if (typeof window !== "undefined" && window.LASP && typeof window.LASP.audit === "function") {
      window.LASP.audit("PIPELINE_" + eventType, { head: _auditChainHead, ...payload });
      // Platzhalter-Hash ("pending:i") sofort finalisieren: audit() ist synchron,
      // verifyChain() wäre bis zum nächsten finalizeChain()-Aufruf rot.
      if (typeof window.LASP.finalizeChain === "function") await window.LASP.finalizeChain();
    }
    return _auditChainHead;
  }

  function getAuditChainHead() {
    return _auditChainHead;
  }

  function resetAuditChain() {
    _auditChainHead = GENESIS_HASH;
  }

  // =============================================================================
  // STUFE 2: Finalize, Wasm-Gating & AES-GCM/PBKDF2 Seal (Versiegeln + Verketten)
  // =============================================================================
  // Schnittstellen-Abstimmung gegen die echten Exporte (KEINE erfundenen APIs):
  //  - verifyChain(): lebt in lasp-core.js (window.LASP.verifyChain) und liefert
  //    { ok, at? } — nicht LASPCrypto. Der Entwurf nahm LASPCrypto.verifyChain an.
  //  - Audit-Zugriff: window.LASP.auditLog (Array) + window.LASP.finalizeChain()
  //    (berechnet die Platzhalter-Hashes "pending:i" asynchron final).
  //  - encryptLog(password, plainText) in lasp-crypto.js: Argument-Reihenfolge
  //    vertauscht gegenüber dem Entwurf, Rückgabe ist ein JSON-BLOB (kein Objekt
  //    mit .iterations) — Iterationen stehen als Konstante im alg-Feld.
  //  - execInSandbox(cap, capPayloadForVerify, issuerPub, io) in lasp-core.js:
  //    erwartet ein signiertes "lasp/cap/v1"-Token (kein { action, payload }-Objekt);
  //    Ergebnisformat ist { ok, reason } statt { allowed }.
  //  - Ein Ketten-Reset nach dem Seal würde das Siegel selbst auslöschbar machen
  //    (append-only-Prinzip) — deshalb bleibt die Kette erhalten; optional kann
  //    NUR der Pipeline-eigene Head zurückgesetzt werden (explicit opt-in).

  const SEAL_ITERATIONS = 100000; // PBKDF2-Iterationen laut deriveKey() in lasp-crypto.js

  async function finalizeAndSealAuditLog(password, options = {}) {
    if (!password || typeof password !== "string" || password.length < 12) {
      throw new Error("SEAL_PASSWORD_INVALID: Minimum 12 characters required for PBKDF2");
    }
    const L = typeof window !== "undefined" ? window.LASP : null;
    const C = _crypto();
    if (!L || !C) throw new Error("SEAL_DEPENDENCY_MISSING: LASP und LASPCrypto müssen geladen sein");

    try {
      // 1. Integrität VOR dem Versiegeln prüfen (Fail-Closed).
      //    Das Audit-Logger-Design in lasp-core.js schreibt synchrone
      //    Platzhalter-Hashes ("pending:i"), die erst finalizeChain() asynchron
      //    zu echten Ketten-Hashes macht. Der Seal verfährt exakt so:
      //    a) Prä-Check auf dem finalisierten Stand von VOR diesem Aufruf
      //       (manipulierte Alt-Einträge fallen hier auf),
      //    b) reguläres finalizeChain() für alle offenen Einträge,
      //    c) Post-Check direkt vor dem Verschlüsseln.
      const preEntries = L.auditLog.filter((e) => !String(e.hash).startsWith("pending:"));
      let chainStatus = { ok: true };
      {
        let prev = "GENESIS";
        for (const e of preEntries) {
          const h = await C.sha256hex(prev + "|" + C.canonical({ i: e.i, ts: e.ts, type: e.type, detail: e.detail }));
          if (h !== e.hash || e.prev !== prev) { chainStatus = { ok: false, at: e.i }; break; }
          prev = e.hash;
        }
      }
      if (!chainStatus.ok) {
        await _auditFinalized(L, "PIPELINE_SEAL_ABORTED", {
          reason: "CHAIN_INTEGRITY_CHECK_FAILED",
          at: chainStatus.at,
          timestamp: Date.now(),
        });
        throw new Error("AUDIT_CHAIN_CORRUPTED_BEFORE_SEAL");
      }
      await L.finalizeChain();
      chainStatus = await L.verifyChain();
      if (!chainStatus.ok) {
        // Theoretischer Zweig: nach frischem finalizeChain() muss die Kette valide
        // sein. Bewusst als Fail-Closed behalten — niemals auf Verdacht versiegeln.
        await _auditFinalized(L, "PIPELINE_SEAL_ABORTED", {
          reason: "CHAIN_INTEGRITY_CHECK_FAILED",
          at: chainStatus.at,
          stage: "post_finalize",
          timestamp: Date.now(),
        });
        throw new Error("AUDIT_CHAIN_CORRUPTED_BEFORE_SEAL");
      }

      // 2. Wasm Capability Check als letztes Gate vor dem Egress/Seal.
      //    Fail-Closed: jeder Verweigerungsgrund (fehlender Issuer, abgelehnte Cap,
      //    Policy-Engine) bricht ab UND wird als PIPELINE_SEAL_ABORTED protokolliert.
      let wasmReason = null;
      try {
        const sealCap = options.cap || (await _buildSealCapability(C, options));
        const wasmCheck = await L.execInSandbox(sealCap.cap, null, sealCap.issuerPub, sealCap.io);
        if (!wasmCheck.ok) wasmReason = wasmCheck.reason;
      } catch (e) {
        wasmReason = e.message;
      }
      if (wasmReason) {
        await _auditFinalized(L, "PIPELINE_SEAL_ABORTED", {
          reason: "WASM_CAPABILITY_DENIED",
          details: wasmReason,
          timestamp: Date.now(),
        });
        throw new Error(`WASM_CAPABILITY_DENIED: ${wasmReason}`);
      }

      // 3. Versiegeln mit dem existierenden AES-GCM/PBKDF2-Primitive.
      //    Klartext-Export nur, wenn explizit gewünscht (sonst Metadaten-Siegel).
      const currentLog = options.exportPlaintext === true
        ? L.auditLog
        : L.auditLog.map(({ i, ts, type, prev }) => ({ i, ts, type, prev }));
      const sealedBlob = await C.encryptLog(password, C.canonical(currentLog));

      // 4. Den erfolgreichen Seal-Vorgang als letzten, verifizierbaren Eintrag
      //    in die Kette schreiben (Beweis = Hash des Blobs, nicht der Inhalt).
      const sealProofHash = await C.sha256hex(sealedBlob);
      L.audit("PIPELINE_SEALED", {
        timestamp: Date.now(),
        sealProofHash,
        pbkdf2Iterations: SEAL_ITERATIONS,
        entryCount: L.auditLog.length,
        pipelineHead: _auditChainHead,
      });
      // Seal-Eintrag in die finale Kette einbinden und erneut prüfen.
      await L.finalizeChain();
      const finalStatus = await L.verifyChain();
      if (!finalStatus.ok) {
        throw new Error("AUDIT_CHAIN_CORRUPTED_AFTER_SEAL");
      }

      // 5. KEIN automatischer Reset der Audit-Kette (append-only: ein Reset nach
      //    dem Seal würde den Siegel-Beweiseintrag zerstören). Optionaler Opt-in:
      if (options.resetPipelineHead === true) resetAuditChain();

      return {
        success: true,
        sealedBlob, // JSON: { alg, salt, iv, data } (AES-GCM-Tag steckt in data)
        sealProofHash,
        chainStatus: finalStatus,
      };
    } catch (error) {
      // Fail-Closed: jeder Fehler wird geworfen, kein stiller Fallback.
      console.error("[LASP Pipeline] Seal failed:", error.message);
      throw error;
    }
  }

  // =============================================================================
  // STUFE 3: Strikte Allowlists & Capability-Revocation für das Seal-Gate
  // =============================================================================
  // Behebt den offenen Punkt aus Stufe 2: _buildSealCapability nutzte null für
  // hostAllow/pathAllow/envAllow — in checkCapability() (lasp-core.js) bedeutet
  // null "Check übersprungen" (stiller Durchlauf). Stufe 3 erzwingt konkrete
  // Listen; unbekannte/leere/wildcard-Einträge werden beim Token-Bau verworfen
  // (fail-closed), sodass ein Token ohne gültige Listen gar nicht erst signiert wird.
  //
  // Revocation: lasp-core.js führt bereits revokedCaps (Set über cap.nonce) und
  // prüft es in checkCapability() VOR ablauf-/scope-checks. Die Pipeline ergänzt
  // eine eigene simulierte Sperrliste REVOKED_CAP_IDS (Modul-Ebene + window.LASP,
  // damit sie zur Laufzeit pflegbar ist) und prüft zusätzlich gegen die echte
  // revokedCaps — doppelte Verriegelung, keine einzelne Vertrauensstelle.
  const SEAL_REVOCATION_LIST_KEY = "REVOKED_CAP_IDS";
  if (typeof window !== "undefined" && !Array.isArray(window.LASP_SEAL_REVOKED_CAP_IDS)) {
    // Initial leer; Einträge = cap.id oder cap.nonce eines zu sperrenden Tokens.
    window.LASP_SEAL_REVOKED_CAP_IDS = [];
  }

  function _revokedCapIds() {
    const lists = [];
    if (typeof window !== "undefined") {
      if (Array.isArray(window.LASP_SEAL_REVOKED_CAP_IDS)) lists.push(window.LASP_SEAL_REVOKED_CAP_IDS);
      if (window.LASP && Array.isArray(window.LASP[SEAL_REVOCATION_LIST_KEY])) lists.push(window.LASP[SEAL_REVOCATION_LIST_KEY]);
    }
    return lists.flat().map(String);
  }

  // Präfix-Matching exakt wie checkCapability(): path.startsWith(p) — deshalb sind
  // "/" und "" als Wildcards verboten (würden den Check wieder aushebeln).
  function _sanitizeAllowList(list, kind) {
    if (!Array.isArray(list) || list.length === 0) {
      throw new Error(`CAP_SCOPE_INVALID: ${kind} muss eine nicht-leere String-Liste sein (kein null-Override, Fail-Closed)`);
    }
    const clean = list
      .filter((v) => typeof v === "string" && v.trim().length > 0 && v !== "*" && v !== "/" && v !== "")
      .map((v) => v.trim());
    if (clean.length === 0) {
      throw new Error(`CAP_SCOPE_INVALID: ${kind} enthält keine gültigen Einträge`);
    }
    return [...new Set(clean)];
  }

  // Audit-Eintrag + Kette sofort finalisieren: audit() schreibt synchrone
  // "pending:"-Platzhalter; ohne Finalisierung schlägt verifyChain() zwischenzeitlich
  // fehl. Die Stufe-3-Protokollierung (DENIED/REVOKED) hält die Kette jederzeit prüfbar.
  async function _auditFinalized(L, type, detail) {
    const entry = L.audit(type, detail);
    await L.finalizeChain();
    return entry;
  }

  // Drei harte Checks VOR jeder Versiegelung. Jeder Fehlschlag schreibt
  // PIPELINE_CAPABILITY_DENIED (reason + timestamp) in die Audit-Kette, BEVOR
  // geworfen wird — kein stiller Durchlauf, kein Werfen ohne Protokoll.
  async function _assertSealCapability(L, cap, io) {
    const deny = async (reason, extra) => {
      await _auditFinalized(L, "PIPELINE_CAPABILITY_DENIED", {
        reason,
        timestamp: Date.now(),
        capId: cap.id || null,
        nonce: cap.nonce || null,
        ...extra,
      });
      throw new Error(`CAPABILITY_DENIED: ${reason}`);
    };

    // 1. Scope-Check: angeforderter Pfad/Host/Env MUSS in der Token-Allowlist liegen.
    //    Zusätzlich: die Allowlist selbst muss die Seal-Operation abdecken (Mindestscope).
    const pathOk = Array.isArray(cap.pathAllow) && cap.pathAllow.some((p) => String(io.path).startsWith(p));
    const hostOk = Array.isArray(cap.hostAllow) && cap.hostAllow.some((h) => io.host === h || String(io.host).endsWith(h));
    const envOk = Array.isArray(cap.envAllow) && Object.keys(io.env || {}).every((k) => cap.envAllow.includes(k));
    if (!pathOk || !hostOk || !envOk) {
      await deny("SCOPE_MISMATCH", {
        scope: { requested: io.path, allowedPaths: cap.pathAllow, host: io.host, allowedHosts: cap.hostAllow },
      });
    }

    // 2. Expiration-Check: exp-Claim muss existieren und in der Zukunft liegen.
    if (!cap.exp || Number.isNaN(Date.parse(cap.exp))) {
      await deny("CAP_EXPIRY_UNPARSEABLE", {});
    }
    if (new Date(cap.exp).getTime() < Date.now()) {
      await deny("CAP_EXPIRED", { expiredAt: cap.exp });
    }

    // 3. Revocation-Check: simulierte Sperrliste (PIPELINE-Seite) UND echte
    //    revokedCaps aus lasp-core.js (Core-Seite) — beide müssen frei sein.
    const ids = [cap.id, cap.nonce].filter(Boolean).map(String);
    const blocked = _revokedCapIds();
    const hit = ids.find((id) => blocked.includes(id));
    if (hit) await deny("CAP_REVOKED", { revokedId: hit, source: "REVOKED_CAP_IDS" });
    if (L.revokedCaps && cap.nonce && L.revokedCaps.has(cap.nonce)) {
      await deny("CAP_REVOKED", { revokedId: cap.nonce, source: "lasp-core.revokedCaps" });
    }
  }

  // Erzeugt die Siegel-Capability im exakten Format des bestehenden PoC-Gates:
  // checkCapability()/execInSandbox() in lasp-core.js erwarten ein "lasp/cap/v1"-Token
  // mit Feldern { tool, hostAllow, pathAllow, envAllow, exp, nonce, issuer } — NICHT
  // eine issueVC()-"lasp/vc/v1"-Credential (deren Feld heißt "capability", nicht "tool").
  // STUFE 3: Keine null-Listen mehr — strenge Defaults, Override nur durch valide Listen.
  const SEAL_DEFAULTS = {
    tool: "lasp-sandbox", // muss in ALLOWED_MODULES (lasp-core.js) enthalten sein
    action: "seal",
    pathAllow: ["/audit/seal"],
    hostAllow: ["localhost", "127.0.0.1"],
    envAllow: [], // Seal braucht keine Umgebungsvariablen -> leeres env besteht jeden Check
    maxAge: 3600, // Sekunden; Obergrenze fuer exp (Default 3600, nicht verhandelbar nach oben)
  };

  async function _buildSealCapability(C, options) {
    const L = typeof window !== "undefined" ? window.LASP : null;
    const keys = options.humanKeys;
    if (!keys || !keys.priv || !keys.did) {
      throw new Error("SEAL_ISSUER_MISSING (options.humanKeys mit priv + did erforderlich)");
    }
    // Overrides nur akzeptiert, wenn sie selbst streng sind (sonst Exception = fail-closed).
    const pathAllow = _sanitizeAllowList(options.pathAllow || SEAL_DEFAULTS.pathAllow, "pathAllow");
    const hostAllow = _sanitizeAllowList(options.hostAllow || SEAL_DEFAULTS.hostAllow, "hostAllow");
    const envAllow = Array.isArray(options.envAllow) ? options.envAllow.map(String) : SEAL_DEFAULTS.envAllow.slice();
    const action = options.action || SEAL_DEFAULTS.action;
    if (action !== SEAL_DEFAULTS.action) {
      throw new Error("CAP_ACTION_UNSUPPORTED: Seal-Token verlangt action 'seal'");
    }
    // maxAge hart gedeckelt: nie länger als SEAL_DEFAULTS.maxAge (3600 s).
    const requestedMaxAge = Number.isFinite(options.maxAge) ? Math.floor(options.maxAge) : SEAL_DEFAULTS.maxAge;
    const ttlSeconds = Math.min(Math.max(requestedMaxAge, 60), SEAL_DEFAULTS.maxAge);

    const cap = {
      kind: "lasp/cap/v1",
      id: "cap-seal-" + C.b64u.enc(crypto.getRandomValues(new Uint8Array(9))),
      tool: SEAL_DEFAULTS.tool,
      action,
      hostAllow,
      pathAllow,
      envAllow,
      exp: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
      iat: new Date().toISOString(),
      nonce: C.b64u.enc(crypto.getRandomValues(new Uint8Array(9))),
      issuer: keys.did,
    };
    cap.signature = await C.sign(keys.priv, cap);

    const io = {
      tool: cap.tool,
      host: options.host != null ? String(options.host) : "localhost",
      path: options.path != null ? String(options.path) : "/audit/seal",
      env: options.env || {},
      amount: 0,
      a: 0,
      b: 0,
    };

    // Stufen-3-Gate VOR execInSandbox: Scope, Expiration, Revocation.
    // execInSandbox prüft dieselben Dinge erneut (Defense-in-Depth) — plus Signatur.
    if (!L) throw new Error("SEAL_DEPENDENCY_MISSING: window.LASP nicht verfuegbar");
    await _assertSealCapability(L, cap, io);

    return {
      cap,
      issuerPub: keys.pub, // CryptoKey aus importKeys — so, wie index.html HUMAN.pub führt
      io,
    };
  }

  // Verwaltung der simulierten Sperrliste (bewusst explizit, kein impliziter Reset):
  async function revokeSealCapability(capIdOrNonce) {
    const id = String(capIdOrNonce || "");
    if (!id) throw new Error("REVOKE_ID_MISSING");
    if (typeof window !== "undefined") {
      if (!Array.isArray(window.LASP_SEAL_REVOKED_CAP_IDS)) window.LASP_SEAL_REVOKED_CAP_IDS = [];
      if (!window.LASP_SEAL_REVOKED_CAP_IDS.includes(id)) window.LASP_SEAL_REVOKED_CAP_IDS.push(id);
      if (window.LASP && typeof window.LASP.audit === "function") {
        window.LASP.audit("PIPELINE_CAPABILITY_REVOKED", { id, timestamp: Date.now() });
        await window.LASP.finalizeChain(); // Kette sofort prüfbar halten (kein "pending:"-Zustand)
      }
    }
    return _revokedCapIds();
  }

  // =============================================================================
  // ÖFFENTLICHE API (window.LASPPipeline statt globales LASP — LASP gehört lasp-core.js)
  // =============================================================================
  const api = {
    evaluateInjectStage,
    enforceHITLApproval,
    finalizeAndSealAuditLog,
    revokeSealCapability,
    getRevokedCapIds: _revokedCapIds,
    SEAL_DEFAULTS,
    getAuditChainHead,
    resetAuditChain,
    GENESIS_HASH,
  };
  if (typeof window !== "undefined") window.LASPPipeline = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
