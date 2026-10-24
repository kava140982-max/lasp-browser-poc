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
  // ÖFFENTLICHE API (window.LASPPipeline statt globales LASP — LASP gehört lasp-core.js)
  // =============================================================================
  const api = {
    evaluateInjectStage,
    enforceHITLApproval,
    getAuditChainHead,
    resetAuditChain,
    GENESIS_HASH,
  };
  if (typeof window !== "undefined") window.LASPPipeline = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
