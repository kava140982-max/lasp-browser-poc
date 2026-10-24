# Changelog

## Unreleased — 2026-10-25

- test: add synthetic adversarial test vectors (Stage 4) — `test-adversarial.js` exercises six hostile vectors (prompt injection with zero-width characters and hidden ARIA markers, capability path violation, revoked token, audit-chain tampering, seal bypass, signature forgery) against `window.LASPPipeline`; all must fail closed (6/6 PASSED).
- fix: revert Python files to JavaScript for browser compatibility — the pipeline reference implementation (`src/lasp-pipeline.js`) and the adversarial test harness are pure JavaScript (jsdom + Node WebCrypto as browser substitute); no Python artifacts remain in the repository.
- security: HITL gate now enforces signature verification on approval (`HITL_SIGNATURE_INVALID` for forged escalations); audit chain stores canonical representations so content drift is detected by `verifyChain()`; `sealAudit()` verifies the chain before any finalization/export (`PIPELINE_SEAL_ABORTED / AUDIT_CHAIN_BROKEN`).

## 0.1.0 — 2026-10-24

- Published the LASP browser proof of concept as a synthetic research laboratory.
- Documented implemented, simulated and out-of-scope components.
- Added GitHub presentation, security reporting, contribution, citation and AI-assisted-development documentation.
- Added local CI checks for JavaScript syntax and SHA-256 integrity.

This release is `SIMULATED_LAB`, `PASS_WITH_LIMITATIONS` and `not_a_certification`.
