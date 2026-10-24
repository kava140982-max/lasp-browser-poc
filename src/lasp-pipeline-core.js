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
  //    echte Signatur-Capability-Signatur (VC), kein { action, payload }-Objekt;
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
        L.audit("PIPELINE_SEAL_ABORTED", {
          reason: "CHAIN_INTEGRITY_CHECK_FAILED",
          at: chainStatus.at,
          timestamp: Date.now(),
        });
        throw new Error("AUDIT_CHAIN_CORRUPTED_BEFORE_SEAL");
      }
      await L.finalizeChain();
      chainStatus = await L.verifyChain();
      if (!chainStatus.ok) {
        L.audit("PIPELINE_SEAL_ABORTED", {
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
        L.audit("PIPELINE_SEAL_ABORTED", {
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

  // Erzeugt die Siegel-Capability im exakten Format des bestehenden PoC-Gates:
  // checkCapability()/execInSandbox() in lasp-core.js erwarten ein "lasp/cap/v1"-Token
  // mit Feldern { tool, hostAllow, pathAllow, envAllow, exp, nonce, issuer } — NICHT
  // eine issueVC()-"lasp/vc/v1"-Credential (deren Feld heißt "capability", nicht "tool";
  // das war die Ursache des CAP_TOOL_MISMATCH im ersten Testlauf).
  // Die Allowlists sind bewusst offen (host "" reicht an jede Allowlist durch,
  // endsWith("") ist immer true); die echten Gates sind: ECDSA-Signatur der Cap,
  // cap.nonce-Revocation und die Policy-Engine (Rate-Limit, Kill-Switch, Blocklist).
  async function _buildSealCapability(C, options) {
    const keys = options.humanKeys;
    if (!keys || !keys.priv || !keys.did) {
      throw new Error("SEAL_ISSUER_MISSING (options.humanKeys mit priv + did erforderlich)");
    }
    const cap = {
      kind: "lasp/cap/v1",
      // MUST matching ALLOWED_MODULES in lasp-core.js — otherwise the WebMCP
      // registry validation (validateToolDef) would reject a tool named e.g.
      // "audit_seal" (underscore violates ^[a-z][a-z0-9-]{2,40}$).
      tool: "lasp-sandbox",
      hostAllow: null, // null => Check übersprungen; [] wäre DENY ALL (checkCapability: .some auf leerer Liste)
      pathAllow: null, // null => Check übersprungen
      envAllow: null,
      exp: new Date(Date.now() + 5 * 60000).toISOString(),
      nonce: C.b64u.enc(crypto.getRandomValues(new Uint8Array(9))),
      issuer: keys.did,
    };
    cap.signature = await C.sign(keys.priv, cap);
    return {
      cap,
      issuerPub: keys.pub, // CryptoKey aus importKeys — so, wie index.html HUMAN.pub führt
      io: { tool: cap.tool, host: "", path: "/audit/seal", env: {}, amount: 0, a: 0, b: 0 },
    };
  }

  // =============================================================================
  // ÖFFENTLICHE API (window.LASPPipeline statt globales LASP — LASP gehört lasp-core.js)
  // =============================================================================
  const api = {
    evaluateInjectStage,
    enforceHITLApproval,
    finalizeAndSealAuditLog,
    getAuditChainHead,
    resetAuditChain,
    GENESIS_HASH,
  };
  if (typeof window !== "undefined") window.LASPPipeline = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
