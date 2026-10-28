# Offline License Manager — design

> V1 baseline design. TPM verifier va migration bo‘yicha yangi amaldagi extension: [TPM attestation design](2026-10-27-tpm-attestation-design.md). Quyidagi dastlabki "keyingi bosqich" izohlari v1 holatini qayd etadi.

## Maqsad
Bitta vendor imzolagan litsenziya aynan bitta server kaliti va apparatiga bog‘lanadi. Flutter/Rust hamda mobil klientlar mTLS gRPC orqali qisqa muddatli lease oladi. Internet kundalik ishlash uchun kerak emas. `max_users` bir vaqtda faol noyob subject soni; bir subject uchun ko‘pi bilan 4 sessiya.

## Ishonch va chegaralar
- Vendor Ed25519 kaliti serverga yetkazilmaydi. JSON envelope ichidagi asl payload baytlari domain/version/key-id bilan imzolanadi.
- Lease va qurilma egaligi uchun ECDSA P-256 ishlatiladi: fizik TPM odatda Ed25519 bermaydi. Public key vendor imzolagan payload ichida bo‘ladi.
- Production `tpm2` rejimi hostdagi Unix socket agentini talab qiladi. Agent kalitini PolicyNV hisoblagichiga bog‘lab provision qilish kerak; software kalitga fallback yo‘q.
- `development` rejimi faqat explicit allow flag bilan ishlaydi. Dasturiy kalit nusxalanadi, shuning uchun bu rejim anti-clone kafolati bermaydi.
- Docker Desktop fizik host TPM’iga teng emas. Fizik TPM, uning provisioning’i va VM anti-clone siyosati real Linux hostda alohida qabul sinovidan o‘tadi.
- Customer root dastur tekshiruvini patch qilishi mumkin. Bu dastur integrity/secure boot o‘rnini bosmaydi. Relay va klonlanadigan vTPM mutlaq himoyalanmaydi.
- Avtomatik ishonchli TPM enrollment/remote attestation va vendor tasdiqlaydigan server migratsiyasi keyingi production bosqichi: noto‘g‘ri "deactivation proof" chiqarilmaydi. Joriy kodda ikkinchi serverga qayta chiqarish vendor registry orqali rad etiladi. Offline fizik serverni ishonchli bekor qilish apparat provisioning bilan birga tekshirilishi shart.

## Kontrakt
LicenseClaims: schema_version=1, license_id, revision, organization_id, product_id, issued_at, not_before, expiration_date (UTC seconds, exclusive), allowed_modules, max_users>0, hardware_profile=dmi-v1, hardware_salt (32 bytes hex), hardware_hash, server_public_key_pem, binding_mode.

ActivationRequest: org, product, hardware profile/salt/hash, server public key, binding mode, random challenge, signature of request domain. Proof of possession is not proof of a genuine TPM: issuer needs trusted physical onboarding.

LeaseClaims: lease_id, request_id, license_id, revision, org, subject, session, modules, issued_at, expires_at. TTL=180 seconds, heartbeat=60 seconds. Session ownership is derived from token and transport auth; bearer leases alone are not accepted by Validate. Server validates persisted active lease as well as signature. No Release RPC: seats expire naturally so still-valid signed leases do not double-spend capacity.

## Server
Rust + tonic + prost; TLS 1.3-capable rustls with a local CA and required client certificates. Authorization: pre-provisioned high-entropy tokens stored as SHA-256 mappings to immutable org/subject. No public admin/import RPC. Import is local admin operation; server reload is a restart.

SQLite WAL, busy timeout, immediate transactions. Persistent state: accepted license id and highest revision plus payload digest (same revision cannot change), high-water wall time, leases, idempotency. Store active lease responses for exact retry. Reject org/product/binding mismatch and missing state after first initialization unless an explicit operator initialize-state step is performed. Local persisted state does not claim TPM rollback resistance.

Acquire validates permitted modules, identity, license window, device challenge and server key; under one transaction checks active distinct users, per-user session cap and idempotency, then signs and commits. Renew requires original owner/session, an unexpired lease, valid current rights and current capacity. Expired or superseded revisions cannot validate. Validate authenticates the caller and checks persisted lease ownership, expiry, requested module and current license. Requested modules cannot expand the lease after acquisition. Limit reduction retains a deterministic set of users (earliest active user, then subject).

Review natijasidagi aniq kontrakt: request ID `unix_seconds:unique_nonce` formatida. Retry oynasi 3600s, kelajak vaqt toleransi 300s. Har subject uchun retained muvaffaqiyatli so‘rovlar ko‘pi bilan 512; ayni retry budget sarflamaydi. Requests expiry timestamp+3600; muddati o‘tgan requests va leases tranzaksiya ichida tozalanadi. Eski request timestamp tozalangandan keyin ham rad etiladi. Revision oshganda yangi Acquire faqat ayni subject/session’ning superseded lease qatorini almashtirishi mumkin; seat boshlanish tartibi saqlanadi va boshqa seat’lar erta bo‘shatilmaydi.

Clock: process wall time is bounded below by startup wall + monotonic elapsed; backwards jumps beyond 300s relative to persistent high-water stop issuance/validation. Reboot state and hardware identity checked before serving. Disk/VM snapshot rollback is outside software-state guarantees.

## Operatsiya
Separate vendor/server/client demo directories. Private vendor key and CA key never mounted into server. Non-root image, read-only root fs, dropped capabilities, persistent DB volume, loopback port publication. Demo generator creates isolated temporary credentials and never overwrites an existing directory.

## Qabul mezonlari
Tampered signature, wrong host, wrong device key, expired license, unknown module, unauthenticated client, cross-subject lease, capacity race, retry, expired renewal, restart, old revision and clock rollback are covered. Docker smoke runs actual TLS gRPC, validates module access and rejects the cloned license on another dev identity. Real TPM test remains explicitly distinct from development/Docker tests.
