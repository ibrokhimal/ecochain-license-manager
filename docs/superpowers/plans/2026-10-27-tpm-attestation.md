# TPM Attestation Implementation Plan

> Execute inline with test-first checks. User asked to continue previously authorized implementation. No Git repository; do not modify outputs/ or host TPM. A code-review subagent is required by requesting-code-review before completion.

**Goal:** Pinned TPM trust, NV attestation, one-time offline migration, reproducible Docker swtpm proof tests.
**Architecture:** Pure bounded Rust TPM parser; vendor Ed25519 challenge; SQLite atomic completion; separate CLI and isolated simulator harness.
**Tech Stack:** Existing Rust dependencies; tpm2-tools + swtpm only in separate test image.
**Spec:** ../specs/2026-10-27-tpm-attestation-design.md

## Global constraints
- No host TPM commands, no replacement of running demo data, no implicit simulator trust.
- Proof original bytes are verified before interpretation; all lengths/types/algorithms constrained.
- TPM key policy must match pinned NV equality; no userWithAuth bypass.
- Migrated entitlements unchanged; activation waits 480s; challenge TTL 86400s.

## Review focus
- Forged AK, wrong nonce/NV Name, trailing/truncated blobs and inactive counters fail.
- Simulator output cannot be upgraded to tpm2 binding.
- Concurrent completion is atomic; exact retry returns same license; stale revision invalidates pending migration.
- Target activation request, org/product and device public key remain bound.
- Proof does not claim malicious-root or prepared-session revocation guarantees.

## Tasks
1. [x] TPM parser tests RED → GREEN; bounded public/attest parsing, NV public type/Name and PolicyNV validation.
2. [x] Migration tests RED → GREEN; trust registry, signed challenges, atomic completion, issuer transaction refactor and activation floor.
3. [x] license-tpm CLI (trust import, challenge, nonce, proof pack, complete, inspect-challenge); actual CLI integration exercised in swtpm container.
4. [x] Two isolated swtpm instances: genuine policy/sign/NV certify and migration; negative counter/password/simulator checks passed.
5. [x] Full cargo tests (28), strict clippy/fmt, main Docker smoke, independent review and docs. Physical host acceptance remains separate.

## Ledger
- Existing baseline: 21 passing tests; software Docker demo is separate from TPM simulation.
- Pinned provisioning chosen over pretending a client-supplied AK is trusted. Manufacturer EK chain bootstrap remains explicitly manual.
- User confirmed physical Linux with TPM 2.0. No SSH/physical-host access supplied; no host TPM state changed. Deployment templates and operator workflow provided.
- Real swtpm exposed restricted AK symmetric template error; fixed to ecc256:ecdsa-sha256:null per official docs; genuine TPM-command flow then passed.
- Reviewer found renewal could shorten migration wait. RED regressions covered attested renewal and ordinary reissue; preserving previous not_before plus issuer floor fixed both. Follow-up reviewer confirmed fix.
- Two pending migration completions raced: exactly one commit, other Revision. 480s wait explicitly assumes 180s lease plus 300s trusted UTC clock bound and local monotonic TTL.
