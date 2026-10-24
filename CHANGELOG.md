# Changelog

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
