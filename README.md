## Status

[![Status: SYNTHETIC_LAB](https://img.shields.io/badge/status-SYNTHETIC__LAB-7c3aed)](./SPEC.md)
[![Assurance: PASS_WITH_LIMITATIONS](https://img.shields.io/badge/assurance-PASS__WITH__LIMITATIONS-f59e0b)](./README.md#status)
[![Security scope: Research prototype](https://img.shields.io/badge/security%20scope-RESEARCH__PROTOTYPE-16a34a)](./SPEC.md)
[![Validation: Synthetic adversarial tests](https://img.shields.io/badge/validation-SYNTHETIC__ADVERSARIAL__TESTS-0ea5e9)](./README.md#status)

LASP is a synthetic browser laboratory for AI-agent security research. It models a fail-closed control pipeline for untrusted content, delegated authority, capability checks, and human-in-the-loop approval under deterministic adversarial test vectors.

This repository is intentionally scoped as a local, inspectable, browser-based prototype. It is designed to make the security logic transparent, challengeable, and testable without claiming production deployment safety, certification, or field validation.

The validation performed here is synthetic and reproducible rather than field-based or certification-grade. It exercises policy enforcement, prompt-injection resistance, scope validation, escalation logic, and audit-chain integrity in a controlled local environment. The project does not claim production security validation, compliance assurance, or real-world deployment safety.

LASP is a research artifact, not a production security boundary, identity system, compliance control, or deployed defense layer. Its value is in making the underlying control logic inspectable, testable, and contestable before any larger system is built around it.

# LASP — AI-Agent Security Proxy

[![Status: SIMULATED_LAB](https://img.shields.io/badge/status-SIMULATED__LAB-7c3aed)](./SPEC.md)
[![Assurance: PASS_WITH_LIMITATIONS](https://img.shields.io/badge/assurance-PASS__WITH__LIMITATIONS-f59e0b)](./README.md#status-und-grenzen)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f)](./LICENSE)
[![GitHub Pages](https://img.shields.io/badge/demo-GitHub%20Pages-222?logo=github)](https://kava140982-max.github.io/lasp-browser-poc/)
![Visitors](https://visitor-badge.laobi.icu/badge?page_id=kava140982-max.lasp-browser-poc&left_text=visitors)

**A local browser proof of concept for safer AI-agent/tool interaction.** LASP explores a fail-closed policy pipeline for untrusted web content, delegated authority, capability checks, human escalation, provenance and auditability.

> **Honest status:** LASP is a synthetic browser laboratory and research prototype. It is **not** a finished security product, certification, compliance claim, production security boundary or independent assurance report.

[Live demo on GitHub Pages](https://kava140982-max.github.io/lasp-browser-poc/) · [M&M story](./MM-STORY.md) · [Specification](./SPEC.md) · [Security policy](./SECURITY.md) · [Contact](mailto:Kava140982@gmail.com)

## Why LASP exists

AI agents increasingly read web pages, tool results and structured interfaces while acting with delegated authority. That creates a security problem: ordinary text can carry indirect prompt injection, a tool can become a confused deputy, and a policy block needs a visible human escalation path instead of a silent failure.

LASP is a compact, inspectable browser PoC for these ideas. It deliberately keeps its scope small, deterministic and local so that the demo can be read, tested and challenged without real credentials, real transactions or external model calls.

## What is implemented and what is simulated?

| Area | Status in this repository |
|---|---|
| 9-stage evaluator: Schema → Auth → Tenant → Data → Inject → Task → Egress → Evidence → Output | **Implemented** as deterministic JavaScript |
| Tool registration and argument validation | **Implemented** with a strict local validator |
| DOM sanitization for selected hidden/ARIA/meta injection markers | **Implemented** and exercised by the demo |
| ECDSA P-256 signatures, DID-like identifiers, envelope and VC-shaped demo objects | **Implemented as browser WebCrypto demo**; not a complete trust ecosystem |
| SHA-256 audit hash chain | **Implemented locally** for reproducible demo evidence; not tamper-proof external logging |
| AES-GCM/PBKDF2 audit export | **Implemented locally**; password and key lifecycle remain demo scope |
| Wasm capability check before a small `add` module | **Implemented**; browser Wasm is not WASI or a host security boundary |
| Q-LLM / P-LLM | **Simulated** by deterministic sanitizer and policy dispatcher; no model call |
| OpenID4VC | **Demo binding only**; no real OIDC/OID4VC flow |
| WebMCP | **Polyfill and validation demo**; not a finished W3C standard implementation |
| Local daemon, browser extension, SDK, production dashboard | **Not included** |

## Quick start

### Option A: open locally

Opening `index.html` may work, but browsers can restrict WebCrypto on `file://` URLs. A local HTTP server is more reliable.

```bash
python3 -m http.server 8000
# open http://127.0.0.1:8000/
```

### Option B: use the hosted demo

Open the [LASP GitHub Pages demo](https://kava140982-max.github.io/lasp-browser-poc/). The app is static and does not require a backend.

### Suggested tour

1. Generate local human and agent demo identities.
2. Issue a human-signed Authority Envelope.
3. Run the playground with a benign request and with `ignore all prior instructions`.
4. Inspect WebMCP registration and DOM sanitization.
5. Test the Wasm capability path and the foreign-host denial.
6. Create a policy block, inspect the HITL queue and verify the audit chain.
7. Run the synthetic evaluator vectors.

## Architecture at a glance

```text
untrusted DOM / prompt / tool output
                │
                ▼
        DOM + Q quarantine layer
                │ typed, reduced data
                ▼
   schema → authority → tenant → data
   → injection → task → egress → evidence
                │
        ┌───────┴────────┐
        ▼                ▼
  policy/capability   human escalation
        │                │
        ▼                ▼
      Wasm demo      signed HITL grant
                │
                ▼
          local audit chain
```

See [SPEC.md](./SPEC.md) for the ten architectural areas and their explicit limitations.

## Security boundaries and known limitations

LASP is a research prototype. Do not use it as a production security boundary, identity provider, payment control, compliance decision, medical system or critical-infrastructure control. The browser owns the runtime; the demo has no server-side trust anchor, no external revocation registry, no real OIDC provider, no WASI host, no independent penetration test and no certification.

The current PoC includes fail-closed signature enforcement in the demo HITL approval path. Treat the PoC nevertheless as a testable research artifact, not as a deployable authorization service; browser runtime, trust anchor, revocation registry, WASI host and independent assurance remain out of scope.

## Research posture

The design is informed by current work on agentic web security, indirect prompt injection, delegated authority, provenance, human control, browser security and accessibility. See the research ledger in the companion Apophis/Argus toolkit and the source links in [SPEC.md](./SPEC.md). Research references are context, not proof that this repository implements or satisfies an external standard.

## AI-assisted development disclosure

LASP was developed under the project responsibility of **Kai Valenta | Apophis Systems** with assistance from ManusKi, Qwen, ChatGPT, DeepSeek, Codex, Claude, Qwen Coder and Perplexity. According to the project statement, there were no human co-developers. These AI systems are not presented as legal authors or rights holders. The repository remains explicitly labelled `SIMULATED_LAB`, `PASS_WITH_LIMITATIONS` and `not_a_certification`.

## License and ownership

The repository currently uses the MIT License. Copyright and project ownership remain with **Kai Valenta | Apophis Systems**, subject to applicable law and any future written agreement. A future commercial or white-label arrangement must be documented separately; a public code license does not itself create a 50:50 revenue agreement, trademark license or exclusivity.

## Contact

For project, research, collaboration or licensing questions:

**Kai Valenta | Apophis Systems**
Email: [Kava140982@gmail.com](mailto:Kava140982@gmail.com)

Additional contact details are intentionally not published here. Please use email to request the appropriate contact channel.

## International topics

`#AI` `#AgentSecurity` `#PromptInjection` `#BrowserSecurity` `#WebMCP` `#WebAssembly` `#Wasm` `#HumanInTheLoop` `#DID` `#VerifiableCredentials` `#PrivacyEngineering` `#SecurityResearch` `#ResponsibleAI` `#OpenSource`

## Contributing and security reports

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request. Vulnerability reports and sensitive findings belong in the process described by [SECURITY.md](./SECURITY.md), not in a public issue.

## Citation

If you reference this research prototype, use the metadata in [CITATION.cff](./CITATION.cff) and cite the specific release or commit.
