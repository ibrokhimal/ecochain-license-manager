# Fizik Linux TPM: aktivatsiya va migratsiya

Bu yo‘riqnoma **ishonchli provisioning orqali oldindan ro‘yxatga olingan TPM** uchun. Vendor oddiy mijoz yuborgan public key’ni avtomatik ishonchli deb qabul qilmaydi. Manufacturer EK CA / MakeCredential trust bootstrap qo‘lda qoladi; pinned AK va NV dalil tekshiruvi avtomatlashtirilgan.

## 1. Tayyorlash

Linux hostda `tpm2-tools`, Python 3, `python3-yaml`, `license-agent`, `license-tpm`, `licensectl` bo‘ladi. Misol Debian/Ubuntu paketlari:

```bash
sudo apt-get install tpm2-tools python3 python3-yaml
```

Binary’lar o‘sha Linux arxitekturasi uchun yig‘ilgan bo‘lishi kerak; macOS `target/debug` binary’larini Linux’ga ko‘chirmang. Docker image’dan mos Linux binarlarini olish yoki `cargo build --release --bins --locked` ishlatish mumkin.

Fizik hostning `/dev/tpmrm0`, UUID va board serial o‘qilishi tekshiriladi. TPM 2.0 SHA-256/P-256, restricted signing AK va NV counter’ni qo‘llashi kerak.

Provisioning skripti aynan `device:/dev/tpmrm0` kernel resource manager’ini talab qiladi. U vaqtinchalik obyektlarni buyruq tugaganda tozalaydi; obyekt `.ctx` faylini `tpm2_flushcontext`ga uzatish noto‘g‘ri. Policy session fayllari esa explicit flush qilinadi. Barcha transient obyektlarni umumiy flush qilmang.

**Provisioning TPM holatini o‘zgartiradi.** Faqat yangi handle’lar uchun xavfsizlik operatori [TPM.md](TPM.md) va skriptni tekshirgach:

```bash
TPM_PROVISION_CONFIRM=CREATE_NEW_LICENSE_KEY \
  bash scripts/tpm-provision.sh /etc/ecochain-license-tpm
```

Handle’lar: lease key `0x81010020`, restricted AK `0x81010021`, NV counter `0x01500020`. Mavjud handle bo‘lsa skript abort qiladi. U TPM clear qilmaydi, owner auth’ni o‘zgartirmaydi va barcha transient context’larni umumiy flush qilmaydi. Avvalgi legacy provisioning bo‘lsa, qayta ishga tushirib kalit almashtirmang; mavjud key/policy’ni saqlagan holda AK qo‘shishni operator alohida boshqaradi.

Owner auth bo‘lsa provisioning uchun `TPM_OWNER_AUTH_FILE=/secure/owner.auth` bering; secret fayl OS ruxsatlari bilan himoyalanadi. Fayl yo‘li argumentga o‘tadi, secret matni o‘tmaydi. Skript auth’ni taxmin qilmaydi va reset qilmaydi.

## 2. Ishonchli manifest

Hostda o‘qish operatsiyalari bilan public manifest oling:

```bash
bash scripts/tpm-collect-trust.sh /var/tmp/license-public-manifest org-123
```

Manifest tarkibi: AK TPM public area va qualified Name, device TPM public area, NV public area va Name, counter, organization/product, UUID va board serial. Unda private key yo‘q. NV public area xeshi attestation’dagi Name bilan tekshiriladi va NV maydoni haqiqiy 8-baytli initialized counter ekanligi tekshiriladi.

Vendor operatori manifestni mijozning ixtiyoriy fayli deb emas, autentifikatsiyalangan physical/factory onboarding natijasi sifatida tasdiqlaydi. So‘ng vendor mashinasida:

```bash
licensectl keygen --out vendor-keys
license-tpm trust-import --registry issuer.db \
  --record license-public-manifest/trust.json \
  --approve-physical-onboarding
```

Mavjud vendor kalitlari bo‘lsa yangisini yaratmang. Trusted device record bir public key uchun o‘zgarmas; uni simulator’dan physical’ga qayta belgilash rad etiladi. Registry backup’i majburiy operatsion vazifa.

## 3. Host agent va activation request

Agentni hostda ishga tushiring (socket papkasi oldindan to‘g‘ri owner/group bilan yaratiladi):

```bash
license-agent --config /etc/ecochain-license-tpm/agent.json \
  --socket /run/ecochain-license/agent.sock
```

`device.json`:

```json
{"kind":"tpm2","socket":"/run/ecochain-license/agent.sock"}
```

```bash
licensectl enroll --device-config device.json --organization org-123 \
  --product ecochain --output activation-request.json
```

Activation request’da hardware salt/hash va TPM kaliti bilan imzolangan proof of possession bor. U vendor ro‘yxatidagi DMI va device key bilan solishtiriladi. Salt/activation faylini keyingi renewal uchun saqlang.

## 4. Vendor challenge

Vendor mashinasida:

```bash
license-tpm challenge --registry issuer.db --key vendor-keys/vendor.key \
  --kind enroll --license-id lic-001 --request activation-request.json \
  --output enroll.challenge
```

Challenge vendor Ed25519 kaliti bilan imzolangan; muddati 24 soat. Faylni va vendor public key’ni hostga yetkazing. Hostda fresh NV dalili chiqariladi:

```bash
bash scripts/tpm-export-proof.sh enroll.challenge target vendor.pub enroll-proof
```

Skript nonce’ni vendor imzosi bilan tekshiradi, keyin `TPM2_NV_Certify` natijasini restricted AK bilan chiqaradi. U **NV hisoblagichini oshirmaydi**. `enroll-proof.json` vendor’ga qaytariladi.

## 5. Litsenziya chiqarish

Vendor’da `terms.json` yarating. Expiration haqiqiy kelajakdagi UTC Unix seconds:

```json
{
  "revision": 1,
  "max_users": 150,
  "modules": ["inventory", "analytics"],
  "expiration_date": 1824595200
}
```

```bash
license-tpm complete --registry issuer.db --key vendor-keys/vendor.key \
  --challenge enroll.challenge --request activation-request.json \
  --target-proof enroll-proof.json --terms terms.json --output org-123.lic
```

Verifier AK imzosi, qualified Name, challenge nonce, aniq NV Name/type/counter, lease key PolicyNV va hardware binding’ni tekshiradi. Challenge consume va litsenziya yozilishi bir SQLite transaction’da. Aynan bir completion qayta yuborilsa o‘sha imzolangan fayl qaytadi; boshqa input bilan qayta ishlatish rad etiladi. Output yozish muvaffaqiyatsiz bo‘lsa shu input’lar bilan yangi output nomiga retry qiling.

`licensectl issue --approve-tpm-enrollment` TPM proof o‘rniga ishlamaydi. Development issue avvalgidek explicit flag bilan qoladi.

Fizik `.lic` `binding_mode=tpm2` oladi. Serverga vendor private key yuborilmaydi. Server konfiguratsiyasi va holatni [TPM.md](TPM.md) bo‘yicha tayyorlang; `--allow-development` ishlatmang. [deploy/](../deploy/) ichida systemd va production Compose shablonlari bor.

## 6. Oddiy renewal

Asl activation request’ni qayta ishlating, yangi enroll challenge/proof oling va `terms.revision`ni oshiring. Amaldagi `not_before` qiymati hech qachon qisqartirilmaydi; migratsiya kutish oynasini renewal bilan chetlab o‘tib bo‘lmaydi.

## 7. Boshqa fizik serverga migratsiya

Yangi server uchun provisioning, manifest trust-import va activation request oldindan tayyor bo‘lishi kerak. Eski va yangi trust record bir environment (physical) va bir org/product’da bo‘ladi.

Vendor’da:

```bash
license-tpm challenge --registry issuer.db --key vendor-keys/vendor.key \
  --kind migrate --license-id lic-001 --request target-activation.json \
  --output migrate.challenge
```

Har ikki hostda challenge tafsilotlarini tasdiqlang:

```bash
license-tpm inspect-challenge --challenge migrate.challenge --public-key vendor.pub
```

License ID, eski/target key hash va amal qilish vaqtini tekshiring. Yangi hostda:

```bash
bash scripts/tpm-export-proof.sh migrate.challenge target vendor.pub target-proof
```

**Eski hostdagi quyidagi operatsiya uning keyingi fresh-policy signing imkoniyatini bekor qiladi. Bu qaytariladigan oddiy fayl operatsiyasi emas.** Xavfsizlik operatori aynan shu litsenziya ko‘chirilishini tasdiqlagach eski agent/License Server’ni to‘xtatadi. So‘ng oldindan ajratilgan counter’ni owner siyosati bilan bir marta oshiradi:

```bash
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_nvincrement -C o 0x01500020
bash scripts/tpm-export-proof.sh migrate.challenge old vendor.pub old-proof
```

Owner auth bo‘lsa site’ning xavfsiz authorization/session usulidan foydalaning; parolni buyruq satriga yozmang. Counter qiymatini yoki agent `counter.bin` faylini yangi qiymatga "moslashtirish" qo‘llab-quvvatlanmaydi: kalitning authPolicy’si eski qiymatga bog‘langan.

Vendor’da:

```bash
license-tpm complete --registry issuer.db --key vendor-keys/vendor.key \
  --challenge migrate.challenge --request target-activation.json \
  --target-proof target-proof.json --old-proof old-proof.json \
  --output migrated.lic
```

Migration `--terms` qabul qilmaydi. Modullar, limit va expiration saqlanadi, revision+1 bo‘ladi. Yangi litsenziya **vendor completion vaqtidan kamida 480 soniya keyin** ishlaydi: 180s eski lease va 300s clock tolerance. Muddat kutish oynasidan oldin tugasa migration rad etiladi. Shu sabab hostga yetkazilgan fayl bilan state init/start qilishni `not_before`gacha kuting.

Bir vaqtda ikki migration completion kelsa faqat bittasi commit qiladi; ikkinchisi stale revision oladi. Proofsiz, noto‘g‘ri target yoki eski counter bilan migration rad etiladi.

## 8. Docker sinovi

```bash
bash scripts/tpm-simulator-test.sh
```

Skript ikkita mustaqil swtpm, haqiqiy `tpm2-tools` va Rust verifier bilan ishlaydi. Host TPM device/socket/kalitlari mount qilinmaydi; test container internetga ulanmaydi. Simulator record faqat `--allow-simulator` bilan qabul qilinadi va **faqat development litsenziyasi** chiqaradi.

Fizik acceptance alohida: haqiqiy hostda DMI, `/dev/tpmrm0`, AK/lease atributlari, owner/NV boshqaruvi, restart, kalit ko‘chirilmasligi va kutish oynasi tekshiriladi. Docker testi fizik apparat sertifikatsiyasi emas.

## Xavfsizlik chegaralari

- NV proof joriy counter’ni isbotlaydi. Agent har sign’da fresh policy session ishlatadi.
- 480s oyna 180s lease va ko‘pi bilan 300s UTC clock skew siyosatiga tayanadi. Klient lokal ishda monotonic TTL’ni uzaytirmasligi shart; mutlaqo ishonchsiz soatni oddiy timestamp bilan himoyalab bo‘lmaydi.
- Malicious root, patched agent, relay yoki oldindan tayyorlangan policy session’larni saqlab qolish ustidan universal revocation kafolati yo‘q. TPM device’ga kirish va agent yaxlitligi OS/deployment tomonidan himoyalanadi.
- Factory trust bootstrap’ni mijoz public key’ni yubordi degan asosda tasdiqlamang. Manufacturer EK trust chain’ni avtomatlashtirish alohida ish.
- Vendor DB rollback va key compromise alohida operatsion xavf; oddiy SQLite MAC’i apparat rollback himoyasi emas.
- Eski server butunlay ishdan chiqib NV proof bera olmasa, avtomatik migratsiya yo‘q. Vendor recovery siyosati alohida tasdiqlanadi.
