// LASP Pipeline — headless-taugliche Referenz-Pipeline (Inject → HITL → Capability → Seal).
// Nutzt ausschließlich window.LASP / window.LASPCrypto — identische Logik wie im Browser-UI (index.html).
// SIMULATED_LAB: WASI = Allowlist-Checks, Q-LLM = deterministischer Sanitizer. Seal = AES-GCM/PBKDF2-Export der finalisierten Audit-Kette.
(function () {
  "use strict";

  const INVISIBLE_CHARS = /[\u200B-\u200D\u2060\uFEFF]/g; // Zero-Width Space/JW/Joiner, BOM, Word-Joiner
  const MIN_SEAL_PASSWORD_LEN = 12;

  function stripInvisible(s) { return String(s ?? "").replace(INVISIBLE_CHARS, ""); }

  // Normalisierung fuer die Injection-Erkennung: unsichtbare Zeichen werden NICHT einfach geloescht
  // (sonst koennte "prior[ZWSP]instructions" zu "priorinstructions" verschmelzen und Marker umgehen),
  // sondern durch ein Leerzeichen ersetzt. Fuer die Weitergabe an den Evaluator gilt der gestrippte Text.
  function normalizeForDetection(s) { return String(s ?? "").replace(INVISIBLE_CHARS, " ").replace(/\s+/g, " "); }

  async function issueCap(humanKeys, tool, hosts, paths, envs, minutes = 10) {
    const C = window.LASPCrypto;
    const cap = {
      kind: "lasp/cap/v1", tool, hostAllow: hosts, pathAllow: paths, envAllow: envs,
      exp: new Date(Date.now() + minutes * 60000).toISOString(),
      nonce: C.b64u.enc(crypto.getRandomValues(new Uint8Array(9))), issuer: humanKeys.did,
    };
    cap.signature = await C.sign(humanKeys.priv, cap);
    return cap;
  }

  // Vollständige Pipeline: DOM/Q-Injection → Evaluator → Envelope → HITL → Capability/Wasm → (optional) Seal.
  // Liefert einen strukturierten Report; fail-closed bedeutet: isBlocked true ODER exec ok false ODER seal ok false.
  async function run(opts = {}) {
    const L = window.LASP, C = window.LASPCrypto;
    if (!L || !C) throw new Error("LASP/LASPCrypto nicht geladen");
    const human = opts.human;
    if (!human) throw new Error("human keys erforderlich");
    const report = { caseId: opts.caseId || "pipe-" + Date.now().toString(36), stages: {}, isBlocked: false };

    // --- Stage INJECT: DOM-Sanitization (echte Marker) + unsichtbare Zeichen vor dem Matcher ---
    const rawVisible = stripInvisible(opts.rawText);
    const domHits = (typeof document !== "undefined" && document.querySelectorAll) ? L.sanitizeDOM(document) : [];
    const invisibleRemoved = rawVisible !== String(opts.rawText ?? "");
    // Q-Stufe sieht die normalisierte Fassung (Zero-Width → Leerzeichen), damit verschmelzende Marker erkannt werden.
    const q = L.quarantine(normalizeForDetection(opts.rawText), { kind: opts.kind || "assess", tenant: opts.tenant || "sandbox-tenant-1" });
    // Zusaetzliche Rohfassung-Auswertung: Quarantine entfernt erkannte Marker; die Pipeline prueft
    // zusaetzlich die normalisierte ROHFASSUNG, damit Blockierflags nicht vom bereinigten Text abhaengen.
    const rawNormLower = normalizeForDetection(opts.rawText).toLowerCase();
    const rawInjectionFlags = Object.entries(L.INJECTION_MARKERS)
      .filter(([, markers]) => markers.some((m) => rawNormLower.includes(m.toLowerCase())))
      .map(([lang]) => "INJECTION_" + lang);
    const rawForbidden = L.FORBIDDEN_MARKERS.some((m) => rawNormLower.includes(m));
    L.audit("Q_SANITIZE", { case: report.caseId, dropped: q.dropped, risk: q.risk, invisibleRemoved });
    report.stages.inject = { domHits: domHits.length, invisibleRemoved, dropped: [...new Set([...q.dropped, ...rawInjectionFlags, ...(rawForbidden ? ["FORBIDDEN_INTENT"] : [])])], risk: q.risk };
    if (q.risk === "high") report.isBlocked = true;

    // --- Stage EVALUATE: 9-Stufen-Evaluator (fail-closed) ---
    const req = {
      schema: "lasp/request/v1", case_id: report.caseId, module_id: opts.module || "lasp-proxy",
      task: opts.taskOverride || q.kind, data_class: opts.dataClass || "public_research", model_route: "local",
      tenant_id: opts.tenant || "sandbox-tenant-1", authorization_id: "lasp-authz-demo-001",
      authorization_verified: opts.authVerified !== false, role: opts.role || "analyst",
      context_payload: normalizeForDetection(opts.rawText), environment_integrity: true,
      external_write: !!opts.externalWrite, forbidden_intent: q.dropped.includes("FORBIDDEN_INTENT") || rawForbidden,
      domain_case: (q.dropped.includes("FORBIDDEN_INTENT") || rawForbidden) ? "forbidden" : undefined,
    };
    const res = L.evaluate(req);
    L.audit("EVALUATE", { case: req.case_id, status: res.status, gate: res.gate, tri: res.tristate });
    report.stages.evaluate = { ...res, flags: [...new Set([...res.flags, ...report.stages.inject.dropped.filter((f) => f.startsWith("INJECTION_") || f === "FORBIDDEN_INTENT")])] };
    if (res.tristate !== "🟢") report.isBlocked = true;

    // --- Stage HITL: Eskalation bei Block; Freigabe nur mit validierter Signatur ---
    if (report.isBlocked) {
      const esc = await L.escalate(human, res.gate + ":" + res.flags.join(","), { case: req.case_id });
      report.stages.hitl = { escalated: true, reason: esc.reason, payloadHash: esc.payloadHash };
      if (opts.approveEscalation) {
        const ap = await L.approve(human, esc.nonce);
        report.stages.hitl.approve = ap;
        if (!ap.ok) report.stages.hitl.blockedBy = ap.reason; // z. B. HITL_SIGNATURE_INVALID
      }
    } else {
      report.stages.hitl = { escalated: false };
    }

    // --- Stage CAPABILITY: Token-Prüfung + Sandbox (Signatur → Revocation → Pfad → Policy → Wasm) ---
    if (opts.cap) {
      const io = { tool: opts.io?.tool || "rechne", host: opts.io?.host || "localhost", path: opts.io?.path || "/tmp/calc", env: opts.io?.env || {} };
      const preDeny = L.checkCapability(opts.cap, io);
      const execRes = await L.execInSandbox(opts.cap, null, human.pub, { ...io, a: 20, b: 22, amount: opts.io?.amount || 0, envelope: opts.envelope });
      report.stages.capability = { preCheckDeny: preDeny, exec: execRes };
      if (!execRes.ok) report.isBlocked = true;
    }

    // --- Stage SEAL: Kette verifizieren, erst dann verschluesselnder Export.
    // sealAudit finalisiert NICHT: ein nachtraegliches Tampering an einer bereits finalisierten Kette
    // wird hier erkannt (fail-closed), statt durch erneutes Hashen kaschiert zu werden.
    if (opts.seal) {
      report.stages.seal = await sealAudit(human, opts.seal.password, opts.seal.requireWasmGating !== false, opts.seal.wasmGatePassed === true);
      if (!report.stages.seal.ok) report.isBlocked = true;
    }
    return report;
  }

  // Seal-Prozess: Weak-Passwort- Gate → Wasm-Gating-Pflicht → verifyChain (VOR Finalisierung!) → AES-GCM-Export.
  // sealAudit finalisiert die Kette NICHT selbst: eine nachtraeglich manipulierte, bereits finalisierte Kette
  // bricht hier mit AUDIT_CHAIN_BROKEN (fail-closed) statt durch erneutes Hashen kaschiert zu werden.
  // Jeder Fehler bricht mit PIPELINE_SEAL_ABORTED ab (fail-closed, nichts wird exportiert).
  async function sealAudit(human, password, requireWasmGating = true, wasmGatePassed = false) {
    const L = window.LASP, C = window.LASPCrypto;
    if (!password || password.length < MIN_SEAL_PASSWORD_LEN) {
      L.audit("SEAL_ABORT", { why: "SEAL_PASSWORD_TOO_WEAK" });
      return { ok: false, reason: "PIPELINE_SEAL_ABORTED", detail: "SEAL_PASSWORD_TOO_WEAK (min. 12 Zeichen)" };
    }
    if (requireWasmGating && !wasmGatePassed) {
      L.audit("SEAL_ABORT", { why: "WASM_GATING_REQUIRED" });
      return { ok: false, reason: "PIPELINE_SEAL_ABORTED", detail: "WASM_GATING_REQUIRED (Capability-Check muss bestanden sein)" };
    }
    // Seal-Reihenfolge (fail-closed): 1) verifyChain auf dem finalisierten Stand — ein Kettenbruch durch
    // nachtraegliches Tampering bricht sofort ab, BEVOR irgendetwas angehaengt oder umgehashen wird.
    // 2) SEAL_ABORT-Eintraege (Diagnostics fehlgeschlagener Siegel-Versuche) werden entfernt; das ist kein
    // Kaschieren von Content-Tampering, denn Schritt 1 hat die Kette bereits als intakt bestaetigt und
    // canon-Drift wuerde weiterhin mit AUDIT_CHAIN_BROKEN brechen (siehe ADV-04).
    // 3) finale Eintraege anhaengen, 4) finalisieren, 5) erneut verifizieren (vollstaendig), 6) verschluesseln.
    const chain = await L.verifyChain();
    if (!chain.ok) {
      L.audit("SEAL_ABORT", { why: "AUDIT_CHAIN_BROKEN", at: chain.at });
      return { ok: false, reason: "PIPELINE_SEAL_ABORTED", detail: "AUDIT_CHAIN_BROKEN@#" + chain.at };
    }
    for (let k = L.auditLog.length - 1; k >= 0 && L.auditLog[k].type === "SEAL_ABORT"; k--) L.auditLog.pop();
    const finalized = await L.finalizeChain();
    if (finalized && finalized.ok === false) {
      L.audit("SEAL_ABORT", { why: finalized.reason });
      return { ok: false, reason: "PIPELINE_SEAL_ABORTED", detail: finalized.reason };
    }
    const post = await L.verifyChain();
    if (!post.ok || post.complete === false) {
      L.audit("SEAL_ABORT", { why: "AUDIT_CHAIN_NOT_COMPLETE", at: post.at ?? -1 });
      return { ok: false, reason: "PIPELINE_SEAL_ABORTED", detail: "AUDIT_CHAIN_NOT_COMPLETE" };
    }
    const bundle = await C.encryptLog(password, JSON.stringify(L.auditLog));
    L.audit("SEAL_DONE", { entries: post.count });
    return { ok: true, entries: post.count, bundleLength: bundle.length };
  }

  window.LASPPipeline = { run, sealAudit, issueCap, stripInvisible, normalizeForDetection, MIN_SEAL_PASSWORD_LEN };
})();
