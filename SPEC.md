# LASP SPEC — AI-Agenten-Sicherheitsproxy

Stand: lokaler Prototyp. `not_a_certification: true`. `SIMULATED_LAB`.
Keine Rechtsinhalte. Keine Sicherheits-/Produktionsreife-Behauptung.

## 1. WebMCP-Schnittstelle (Tool-Registrierung)

- API: `document.modelContext.registerTool({name, description, inputSchema, run})`
- Polyfill falls Browser-API fehlt (ehrlich gelabelt: `polyfilled: true`).
- Strikte Validierung: `name` = `^[a-z][a-z0-9-]{2,40}$`, `description` 10–500 Zeichen,
  `inputSchema` muss `type:object` mit `properties` + `additionalProperties:false` sein.
- Jeder Tool-Aufruf validiert Args gegen `inputSchema` (Typ, required, enum, min/max, Muster).
- DOM-Sanitization VOR Registrierung + vor jedem Q-Durchlauf:
  entfernt/neutralisiert versteckte Injections in `aria-label`, `aria-hidden="true"`-Inhalten,
  `<meta name=...>`-Tags und HTML-Kommentaren. Fundstellen werden im Audit geloggt,
  Originaltext wird NIE an P-LLM/Tools weitergereicht.

## 2. Dual-Agenten-Laufzeit (Privilegientrennung)

- **Q-Stufe (Quarantäne):** bekommt ausschließlich Rohdaten (DOM-Text, Tool-Output, User-Prompt).
  Keine Tool-Rechte (`tools: []`). Gibt NUR typisierte Structs aus:
  `{kind, fields, quotes[], dropped[], risk}`. Alles andere wird verworfen.
  In diesem Prototyp deterministisch (Regex + Marker + Schema), kein Modellaufruf.
- **P-Stufe (privilegiert):** besitzt Tool-Rechte, bekommt NUR Q-Structs + Authority-Envelope
  + Policy-Freigabe. Direkter Rohdaten-Zugriff ist ein Fehler (wird rot 🟡/🔴).
- Regel: P führt nie String-Anweisungen aus Q-Daten aus („Daten sind Daten").

## 3. Authority Envelope (mensch-kompiliert)

Wird vom Menschen gebaut, nicht vom Agenten. Serverseitig (hier: vor Dispatch) validiert:

```json
{
  "principal": "did:lasp:... (Mensch)",
  "agent": "did:lasp:... (P-LLM)",
  "scope": {"tools": ["rechne", "speichere"], "tenants": ["sandbox-tenant-1"], "maxCalls": 5},
  "window": {"notBefore": "...", "notAfter": "..."},
  "killSwitch": true,
  "nonce": "...",
  "signature": "ECDSA-P256 über alles außer signature"
}
```

Verhindert Confused-Deputy: jedes Tool-Arg wird gegen scope/tools/tenants/Fenster/Calls geprüft.
Abgelaufen, überzählig oder fremd-tenant → 🟡 Block + HITL. Kill-Switch stoppt alles sofort.

## 4. Kryptografische Identität (VC/DID)

- `did:lasp:<base64url(SHA-256(P-256-pubkey))>` für Mensch + Agenten.
- W3C-VC (vereinfacht, ehrlich): `{issuer, subject, capability, scope, exp, signature}`.
  Delegationskette Mensch → Q → P ist verifizierbar (Signaturkette im Audit).
- OpenID4VC: hier nur Demo-Bindung (DID + Signatur-Challenge), kein echter OIDC-Flow.

## 5. Wasm-Capability-Sandbox

- Standard-Laufzeit für Tool-Ausführung. Hier: echtes Wasm-Modul (`add(i32,i32)->i32`).
- Capability-Token: `{tool, hostAllow, pathAllow, envAllow, exp, attenuations[], revoked[], signature}`.
  Rechte default null. Nur einschränkbar (attenuatable), widerrufbar (Denylist im Speicher).
- Ablauf: Token-Signatur prüfen → Allowlist prüfen (Host/Pfad/Env) → Policy prüfen →
  Wasm instanziieren → ausführen mit Timeout. Jede Verletzung → 🟡/🔴, kein Exec.

## 6. Deterministische Policy-Engine (Pre-Execution)

Läuft VOR der Sandbox. Harte Regeln:
- Transaktionslimit pro Call + Tagesbudget, Velocity (max Calls / 60 s),
  Händler-/Host-Blocklist, Zeitfenster, sensible Datenklassen (`clinical_pii`, `classified` → block).
- Zahlungen/Datenexport brauchen zusätzlich Envelope-Scope + HITL-Freigabe.
- Bei Überschreitung: Block bevor Sandbox erreicht wird (mit Risikoscore + Grund).

## 7. Verifizierter Persistenz-Speicher

- Kein Totalverbot. Jeder Write: `{key, value, sessionId, ts, sig(Mensch-Key)}`.
- Jeder Read: Signatur + Session-Bindung prüfen, sonst verweigern + Audit-Eintrag.
- Session-Wechsel macht fremde Writes unlesbar (Tenant-Isolation light).

## 8. HITL-Eskalations-Gateway

- Fängt Policy-Blocks + Scope-Überschreitungen ab.
- Erzeugt signierte, zeitgebundene Eskalation (5 Min TTL) an den Menschen.
- Nur explizite manuelle Freigabe (VC-signiert) hebt Block auf oder erweitert Scope temporär.
- Keine Auto-Freigabe, kein Timeout-Auto-OK.

## 9. Forensik-Audit-Logger

- Append-only, Hash-kette (`prevHash → SHA-256(prevHash+canonical(entry))`).
- Jeder Intercept/Block/Override/Provenienz-Schritt mit Timestamp + Payload-Hash.
- Lokal AES-GCM-verschlüsselt (Master-Passwort via PBKDF2). Kein Auto-Upload.
  Export nur nach manueller Entschlüsselung. Master-Passwort wird nie gespeichert.

## 10. Tri-State Assurance Evaluator

- 9 Stufen fail-closed: `Schema → Auth → Tenant → Data → Inject → Task → Egress → Evidence → Output`.
- Ausschließlich: 🟢 Konform (alle Gates ok) · 🟡 Valide Struktur, Policy-Block (Autorisierung/Policy/HITL-pflichtig) · 🔴 Struktur invalide (Schema/Typ/Limit).
- Erster Fehler gewinnt (fail-closed), kein Weiterprüfen nach Block.
- Synthetisch testbar: Demo-Vektoren (benigne / mehrsprachige Injection / Forbidden-Intent /
  Tenant-Mismatch / Budget-Overflow) mappen deterministisch auf 🟢🟡🔴 — ohne binäres Pass/Fail-Theater.
