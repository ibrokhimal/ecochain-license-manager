# License Manager Implementation Plan

> **For agentic workers:** Execute inline with superpowers:executing-plans. Track results here; use test-first checks. No Git repository exists, so do not initialize or commit unrelated workspace files.

**Goal:** Offline bitta-server litsenziyalash, Rust gRPC server, vendor CLI, client CLI va Docker demo.

**Architecture:** Ed25519 signed raw JSON license; P-256 device/lease signature; explicit software development signer or required host TPM agent; SQLite seat registry; mTLS plus subject token. Physical TPM migration certification is a separately documented deployment gate, not simulated security.

**Tech Stack:** Rust, tonic/prost, ed25519-dalek 2.2, p256 0.13, rusqlite, Docker Compose.

**Spec:** ../specs/2026-10-27-license-manager-design.md

## Global Constraints
- No vendor private key in server image or mounts; no unsigned license or implicit development fallback.
- TTL=180s; heartbeat=60s; max 4 sessions per subject; license expiration exclusive.
- Persistent count is distinct authenticated subject; exact idempotent retry; no early seat release.
- Production TPM and software Docker demo must be clearly distinguished.

## Review Focus
- An exact retry after restart must preserve the original signed response and not mint another seat.
- Same revision with changed payload and expired renewal must be rejected.
- Duplicate sessions, parallel final-seat acquisition and cross-subject use must not bypass limits.
- A software license must fail default production startup even if signature is valid.
- Existing outputs/ and customer host TPM state must not be changed.

## Task 1 — License and identity core
Files: Cargo.toml, build.rs, proto/license.proto, src/{lib,license,device,error}.rs, tests/core.rs.
- [x] Write tests for valid verification, tampering, host/key mismatch, expiration and dev-mode refusal; run RED.
- [x] Implement signed envelope, claims validation and fingerprint; run GREEN.

## Task 2 — Persistent leases
Files: src/{store,engine}.rs, tests/leases.rs.
Interfaces: Engine::acquire, renew, validate take authenticated Principal and explicit observed time; device trait supplies public key, fingerprint and signing.
- [x] Write tests for capacity, idempotency, session ownership/cap, expired renewal, module denial, restart, clock/revision rollback, concurrency; run RED.
- [x] Implement immediate transaction state and signed leases; run GREEN.

## Task 3 — TLS gRPC and operator tools
Files: src/{rpc,config}.rs, src/bin/{license-server,licensectl}.rs, tests/rpc.rs.
- [x] Write TLS integration test for acquire/renew/validate and wrong/missing identity; run RED.
- [x] Implement CLI demo/keygen/enroll/issue/client and TLS server with explicit token mapping; run GREEN.
- [x] Issuer SQLite issuance registry refuses second binding for same license id and lower/equal changed revisions.

## Task 4 — Host TPM adapter
Files: src/agent.rs, src/bin/license-agent.rs, scripts/tpm-provision.sh, docs/TPM.md.
- [x] Test Unix socket sign roundtrip and rejection of non-domain signing input; run RED.
- [x] Implement Linux DMI collector and bounded tpm2-tools subprocess adapter; Unix adapter test GREEN. Physical TPM not available/tested.
- [x] Document PolicyNV provisioning, local deactivation and production enrollment/migration gates. Never run destructive TPM commands automatically.

## Task 5 — Docker packaging and verification
Files: Dockerfile, compose.yaml, scripts/{smoke.sh,docker-smoke.sh}, README.md, docs/FLUTTER.md.
- [x] Document Uzbek setup and commands, secret boundaries, heartbeat and failure behavior.
- [x] Run fmt, clippy, full cargo test and real local mTLS gRPC integration. 21 tests pass.
- [x] Build Docker and execute demo: mTLS acquire/validate/renew, ownership, module limit, seat limit, copied-license rejection on server B and persistent state after restart all passed. Physical TPM remains a deployment gate.

## Progress / rulings
- Workspace is not a Git repository; new isolated license-manager/ directory avoids existing outputs.
- User explicitly asked for plan and implementation together; continue through reversible implementation without another approval gate.
- Inline security review used a fresh read-only reviewer as required by requesting-code-review skill. Found and fixed unbounded request history, revision session recovery and delimiter collision; regression tests observed RED then GREEN. Follow-up reviewer confirmed all three resolved, no important new issues in fixes.
- Request-retention change is intentionally part of the protocol: timestamped IDs allow old records to be pruned without permitting stale retries to mint new leases.
- Final evidence: `cargo test --all-targets --locked` = 21 passed; `cargo fmt --check` and strict Clippy passed; Docker release build and `bash scripts/docker-demo.sh --skip-build` passed. Demo server is left running on loopback port 50051 for the user.
- Packaging ruling: Docker internal bridge suppressed host port publishing in this Engine; switched to normal bridge with loopback-only binding, added host TCP assertion, reran all Docker smoke checks and verified native host mTLS status successfully. Actual air-gap egress is a host/network firewall policy, not claimed from Docker networking alone.
