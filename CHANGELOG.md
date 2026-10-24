# Changelog

## Unreleased — Stufe 3 (Strikte Allowlists & Capability-Revocation)

- `src/lasp-pipeline-core.js`: `_buildSealCapability` no longer emits `null` allowlists
  (which `checkCapability()` treats as "skip check" = silent pass-through). Strict
  defaults are now baked into every seal token: `pathAllow: ["/audit/seal"]`,
  `hostAllow: ["localhost", "127.0.0.1"]`, `envAllow: []`, `action: "seal"`,
  `maxAge` hard-capped to 3600 s with an `exp` claim; wildcard entries (`*`, `/`, ``)
  and empty lists are rejected at token build time (`CAP_SCOPE_INVALID`, fail-closed).
- New three-stage gate `_assertSealCapability()` runs before `execInSandbox()`:
  scope check (path/host/env vs. token allowlist), expiration check (`exp` claim),
  revocation check against both the simulated pipeline blocklist
  (`window.LASP_SEAL_REVOKED_CAP_IDS` / `LASP.REVOKED_CAP_IDS`) and the real
  `LASP.revokedCaps` set. Every denial writes a `PIPELINE_CAPABILITY_DENIED` entry
  (reason + timestamp + capId/nonce) to the audit chain BEFORE throwing — no throw
  without a record, no silent pass-through.
- Public API additions: `LASPPipeline.revokeSealCapability(capIdOrNonce)` (audits a
  `PIPELINE_CAPABILITY_REVOKED` entry), `getRevokedCapIds()`, `SEAL_DEFAULTS`.
- Chain hygiene fix: all pipeline audit writes (mirrored stage events, seal aborts,
  denials, revocations) now finalize the hash chain immediately, so `verifyChain()`
  stays green between calls instead of exposing transient `pending:` placeholders.
  No behavior change to `finalizeAndSealAuditLog` semantics or `verifyChain` itself.
- Verified by Node/WebCrypto integration test (`test-stage3.js`): 23 checks green
  (happy-path seal, strict-token success, wildcard/empty-list rejection, foreign
  path/host denial with DENIED-before-throw ordering, expired-token denial via core
  gate and via `options.cap`, revoked-nonce end-to-end denial, stage A/B regression,
  final `verifyChain()` over all events).

## Unreleased — Stufe 2 (Finalize, Wasm-Gating & AES-GCM/PBKDF2 Seal)

- Extended `src/lasp-pipeline-core.js` with `finalizeAndSealAuditLog(password, options)`:
  chain-integrity pre-check on the finalized state (tampering surfaces before sealing;
  a blind re-hash would erase it), real `execInSandbox` capability gate (signed
  `lasp/cap/v1` token in the exact format `checkCapability()` expects), sealing via the
  existing `LASPCrypto.encryptLog` (PBKDF2-100k/AES-GCM-256), and an append-only
  `PIPELINE_SEALED` proof entry (`sha256` of the sealed blob). Fail-closed on every path:
  weak password, missing issuer, denied capability, corrupted chain — aborts are logged as
  `PIPELINE_SEAL_ABORTED` before anything is encrypted. No automatic chain reset after
  sealing (append-only); opt-in via `options.resetPipelineHead`. Default seal is
  metadata-only (`i/ts/type/prev`); full detail export requires `options.exportPlaintext`.
- Verified by a Node/WebCrypto integration test against the real modules: 17 checks green
  (happy path, decrypt roundtrip, wrong-password GCM rejection, tamper detection, all
  fail-closed gates).

## Unreleased — Stufe-1-Iteration (B → A → C)

- Added `src/lasp-pipeline-core.js`: browser-compatible pipeline module exposing `window.LASPPipeline`
  with the inject-stage evaluator (fail-closed on invisible Unicode / suspicious DOM markers),
  HITL ECDSA-P-256 signature enforcement (no silent pass-through; rejections are audited too),
  and a SHA-256 audit hash chain anchored to a 64-zero genesis head.
- The module reuses the existing real WebCrypto primitives (`LASPCrypto`) and mirrors every pipeline
  event into the established append-only audit log of `lasp-core.js` (`finalizeChain`/`verifyChain` remain authoritative).
- Loaded the new script in `index.html`; refreshed `SHA256SUMS.txt`.

## 0.1.0 — 2026-10-24

- Published the LASP browser proof of concept as a synthetic research laboratory.
- Documented implemented, simulated and out-of-scope components.
- Added GitHub presentation, security reporting, contribution, citation and AI-assisted-development documentation.
- Added local CI checks for JavaScript syntax and SHA-256 integrity.

This release is `SIMULATED_LAB`, `PASS_WITH_LIMITATIONS` and `not_a_certification`.
