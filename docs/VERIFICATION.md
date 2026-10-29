# Tekshirish natijalari — 2026-10-27

**Joriy v2 natija:** 28 ta Rust testi, strict Clippy/fmt, haqiqiy swtpm NV attestation/migration va yangilangan mTLS Docker demo o‘tdi. Dastlabki Rust/Docker bo‘limlari v1 baseline; v2 tafsilotlari oxirida.

## Rust

`cargo test --all-targets --locked`: **21 passed, 0 failed**.

- Core: 8 — vendor signature, tampering, hardware/key binding, exclusive expiration, production dev refusal, enrollment proof, issuer registry and delimiter collision.
- Leases: 10 — atomic final seat, distinct users, exact retry, module/owner, expiry, restart, clock/revision rollback, session cap, revision recovery, bounded history and request budget.
- Unix agent: 1 — public key/fingerprint/sign roundtrip, unrelated signing domain denied. Software test signer only.
- Operator CLI: 1 — demo, enrollment, issue, inspect, vendor key separation, default production refusal and copied-license failure.
- TLS gRPC: 1 — actual local mTLS channel, Alice/Bob separation, module/seat limits, invalid bearer and missing client certificate.

`cargo fmt --check` va `cargo clippy --all-targets --locked -- -D warnings`: **passed**.

## Docker

`docker compose build license-server`: **passed**, Linux ARM64 release image `ecochain-license:local`.

`bash scripts/docker-demo.sh --skip-build`: **passed**.

```json
{"checks":["mtls","acquire","idempotency","validate","capacity","owner","module","renew","renew-idempotency"],"smoke":"passed"}
```

- Server B’da ayni `.lic` boshqa apparat/kalit identifikatsiyasi bilan rad etildi.
- Server A restart qilindi; status `active_users=1`, `max_users=1`, `revision=1` bo‘lib saqlandi.
- Hostdagi `target/debug/licensectl status --credentials demo/client` orqali Docker serverga `https://127.0.0.1:50051` manzilida haqiqiy mTLS gRPC ulanishi ham passed. Dastlabki internal-network port publishing xatosi bridge bilan tuzatildi va Docker smoke qayta to‘liq o‘tdi; skript host TCP portini ham tekshiradi.
- Demo server loopback `127.0.0.1:50051`da ishlayotgan holatda qoldirildi. TCP gRPC mTLS endpoint; brauzer sahifasi emas.
- Containerlar Docker bridge tarmog‘ida; port faqat host loopback’da publish qilinadi. Serverga vendor private key mount qilinmaydi.

Compose konfiguratsiyasi va ikkala shell skript sintaksisi tekshirildi. Fresh read-only code reviewer uchta muammoni topdi; regressiya bilan tuzatildi va reviewer tuzatishlarni qayta tekshirdi.

## Sinovdan o‘tmagan / implementatsiya qilinmagan

- Fizik TPM’da provisioning, PolicyNV va private key’ning apparatga bog‘lanishi: kod/yo‘riqnoma bor, haqiqiy apparatda tekshirilmagan. Host TPM holatiga hech qanday buyruq yuborilmadi.
- Manufacturer EK CA / MakeCredential bootstrap avtomatlashtirilmagan. Pinned AK’dan keyingi NV proof va migration verifier v2’da implementatsiya qilingan va swtpm’da tekshirilgan.
- Mavjud Flutter/GetX/FRB ilovaga integratsiya: bu workspace’da ilova yo‘q; integratsiya kontrakti berilgan.
- HA, korporativ identity provider lifecycle va hardware-backed state rollback: production bosqichida alohida talablar.

Development kaliti faylda; Docker sinovi TPM anti-clone kafolati emas. To‘liq software key+identity nusxasi development rejimida ko‘chirilishi mumkin. Production server development litsenziyasini explicit flag bo‘lmasa rad etadi.

## V2 — pinned TPM attestation va migration

`cargo test --all-targets --locked`: **28 passed, 0 failed**. Core 9, leases 10, agent 1, operator 1, mTLS RPC 1, TPM parser 3, migration 3.

`cargo fmt --check` va `cargo clippy --all-targets --locked -- -D warnings`: **passed**.

Isolated swtpm Docker testi:

```json
{"swtpm":"passed","checks":["real-NV-policy","password-bypass-denied","restricted-AK-attestation","active-old-migration-denied","fresh-sign-after-increment-denied","one-time-migration","exact-retry","480-second-wait","renewal-preserves-wait","unchanged-entitlements","simulator-development-only"]}
```

Ikki mustaqil swtpm state’da haqiqiy tpm2-tools key yaratish, PolicyNV, TPM2_Sign va TPM2_NV_Certify bajarildi. Rust raw TPM public/attestation bytes va DER imzoni tekshirdi. NV public hash/Name, counter type, restricted AK, lease key authPolicy va password bypass yo‘qligi tekshirildi. Host fizik TPM, vendor credential yoki workspace mount qilinmagan.

Yangilangan image bilan `bash scripts/docker-demo.sh --skip-build`: **passed**. Loopback port, gRPC acquire/renew/validate, user/module limits, server B rejection va persistent restart qayta tekshirildi. Demo ishlayotgan holatda qoldirildi; mavjud demo fayllari almashtirilmadi.

Production Compose `config --quiet` va shell skriptlar `bash -n` bilan tekshirildi. systemd unit va physical collector/provisioning real hostda ishga tushirilmagan. Optional owner file authorization bor; haqiqiy owner secret ishlatilmagan.

Read-only reviewer topgan renewal wait bypass’i regression RED → GREEN bilan tuzatildi; issuer ham not_before qisqarishini rad etadi. Follow-up review tuzatishni tasdiqladi. Parallel completion testi bitta commit va bitta stale revision natijasini tekshiradi.

Foydalanuvchi production fizik Linux TPM 2.0 ekanini tasdiqladi. Hali bajarilmagan: aynan shu hostda DMI/TPM ACL, firmware/owner policy, reboot, systemd va private-key non-migration acceptance. Pinned bootstrap va prepared-session/root/relay chegaralari [TPM_WORKFLOW.md](TPM_WORKFLOW.md)da.

## Fizik TPM sinovi — 2026-10-29

Yuqoridagi fizik host tekshirilmaganligi haqidagi yozuvlar avvalgi bosqich holati. Keyingi sinov Ubuntu 24.04 x86_64 va fizik Intel TPM 2.0’da operator ruxsati bilan bajarildi:

- SHA-256, ECDSA va NIST P-256, DMI UUID/serial mavjudligi tekshirildi.
- Ajratilgan NV counter, policy-only signing key va restricted signing AK yaratildi. Mavjud boshqa TPM obyektlari saqlandi.
- Kernel resource manager bilan obyekt `.ctx` faylini flush qilish xatosi tuzatildi; sessiyalar explicit tozalanadi, global flush ishlatilmaydi.
- Capability’siz systemd agentga TPM device uchun `tss` supplementary group kerakligi aniqlandi va tuzatildi. Agent `active`, socket `0660`, konfiguratsiya katalogi `0700`, konfiguratsiya `0600`.
- Rust agent bilan haqiqiy TPM activation request imzolandi.
- Public manifest vendor registry’ga trusted physical onboarding sifatida kiritildi. Vendor challenge uchun restricted AK orqali NV proof olindi va Mac’dagi Rust verifier bilan tekshirildi.
- `simulator_allowed=false` bilan 7 kunlik TPM-bound test `.lic` chiqarildi va Linux’ga yuborildi. Vendor private key Linux’ga yuborilmadi; test materiallari public Git’dan tashqarida saqlandi.

SSH tarmoq aloqasi uzilgani uchun fizik `.lic` bilan Docker/mTLS smoke hali bajarilmadi. Fizik hostlar orasidagi migratsiya, NV deaktivatsiya, reboot va to‘liq production acceptance hali ochiq.
