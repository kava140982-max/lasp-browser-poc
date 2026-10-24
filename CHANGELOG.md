# Changelog

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
