# Fizik TPM deployment

## Joriy implementatsiya va chegarasi

`license-agent` Linux fizik hostda `tpm2-tools` orqali P-256 kalit bilan imzolaydi. Har imzolashda yangi policy session ochiladi va `PolicyNV == activation_counter` talabi tekshiriladi. Private key fayldan yuklanmaydi va software signing’ga fallback yo‘q. `tpm2_sign`ning DER imzosi Rust’da yana tekshiriladi.

Kod macOS Docker Desktop’da fizik TPM testidan o‘tgan deb hisoblanmaydi. Docker demo dasturiy signer bilan ishlaydi. Quyidagi provisioning skripti avtomatik demo yoki test tomonidan chaqirilmaydi; fizik apparatda operator tekshiruvi talab etiladi.

Yangilanish: pinned AK/NV attestation verifier va offline migration qo‘shilgan. Amaldagi bosqichma-bosqich buyruqlar [TPM_WORKFLOW.md](TPM_WORKFLOW.md)da; dastlabki boolean-only TPM issuance yo‘li endi rad etiladi.

## Talablar

- Linux host va `/dev/tpmrm0` bilan fizik TPM 2.0.
- ECDSA P-256, SHA-256 va NV policy operatsiyalarini qo‘llash.
- `tpm2-tools`, Rust yoki mos Linux release binary.
- Host UUID va board serial haqiqiy bo‘lishi kerak; bo‘sh/placeholder identifikatsiyada fail closed.
- Secure/Measured Boot, TPM hierarchy authorization, root/operator huquqlari va physical presence siyosati tashkilot tomonidan boshqariladi.
- Ushbu template `0x01500020` NV index, `0x81010020` lease key va `0x81010021` restricted AK’dan foydalanadi. Band bo‘lsa skript abort qiladi; mavjud kalitlarni o‘chirmaydi.

## Provisioning

Skript yangi NV counter va kalit yaratib host TPM holatini o‘zgartiradi. Avval xavfsizlik operatori tekshiradi. Skript owner auth’ni almashtirmaydi va TPM’ni clear qilmaydi. Owner auth kerak bo‘lsa `TPM_OWNER_AUTH_FILE` orqali himoyalangan fayl yo‘lini bering: tpm2-tools `file:` authorization ishlatadi, parol argv’ga yozilmaydi. Skriptning qisman muvaffaqiyatsiz bajarilishi uchun avtomatik rollback yo‘q: qolgan handle’larni operator tekshiradi.

```bash
TPM_PROVISION_CONFIRM=CREATE_NEW_LICENSE_KEY \
  bash scripts/tpm-provision.sh /etc/ecochain-license-tpm
```

Yaratilgan kalit atributlari `fixedtpm|fixedparent|sensitivedataorigin|sign`; **userwithauth yo‘q**. Aks holda policy’ni chetlab password authorization bilan imzolash yo‘li qolishi mumkin. Vendor onboarding’da `tpm2_readpublic` orqali atributlar va `authPolicy` tekshiriladi.

`counter.bin` — aktivatsiya hisoblagichining kutiladigan 8 baytli big-endian qiymati. Bu maxfiy kalit emas; lekin o‘zboshimchalik bilan almashtirilmaydigan root-owned konfiguratsiya bo‘lishi kerak. Kalitning policy digesti aynan shu qiymat va NV Name bilan bog‘lanadi.

## Host agent

Hostda `license-tpm` kabi servis foydalanuvchisini yarating. Unga TPM device, DMI fayllari va konfiguratsiyani o‘qish uchun minimal ruxsat bering. Agent socket papkasi faqat tegishli servis guruhiga ochiq bo‘lsin:

```bash
license-agent \
  --config /etc/ecochain-license-tpm/agent.json \
  --socket /run/ecochain-license/agent.sock
```

Socket `0660` bilan yaratiladi. systemd’da `RuntimeDirectory=ecochain-license`, mos `User`/`Group` ishlating; servis to‘xtaganda runtime papka tozalansin. Mavjud socket yo‘li agent tomonidan o‘zboshimchalik bilan o‘chirilmaydi. `tpm2-tools` PATH host administratori nazoratida bo‘ladi.

Server config’dagi device bo‘limi:

```json
{
  "kind": "tpm2",
  "socket": "/run/host-license/agent.sock"
}
```

Docker’da host socket papkasini `/run/host-license`ga read-only mount qiling va kerakli guruh GID’ni `group_add` bilan bering. Read-only socket mount RPC chaqiruvlarini to‘xtatmaydi; host guruh ruxsatlari muhim. Docker container’ga privileged rejim, Docker socket yoki barcha `/sys` mount’larini bermang.

## Offline aktivatsiya

1. Hostda yuqoridagi device bo‘limini `device.json`ga yozing.
2. Activation request yarating:

```bash
licensectl enroll --device-config device.json \
  --organization org-123 --product ecochain \
  --output activation-request.json
```

3. Vendor mashinasida kalitlar alohida yaratiladi:

```bash
licensectl keygen --out vendor-keys
```

4. Vendor operatori ishonchli public manifestni `license-tpm trust-import --approve-physical-onboarding` bilan ro‘yxatga oladi; signed challenge chiqaradi, host restricted AK bilan fresh NV proof qaytaradi, vendor `license-tpm complete` bilan issue qiladi. [To‘liq workflow va buyruqlar](TPM_WORKFLOW.md).

Oddiy activation imzosi faqat key possession’ni isbotlaydi. Manufacturer EK CA trust bootstrap avtomatlashtirilmagan; pinned AK’dan keyingi nonce/NV/policy tekshiruvi avtomatik. `--approve-tpm-enrollment` proof o‘rniga ishlamaydi.

5. Mijozga faqat `.lic` va `vendor.pub` yetkaziladi. Server config’da org/product, public key, license yo‘li, TPM socket va lokal mTLS credential’lar ko‘rsatiladi.
6. Holatni bir marta explicit yarating, keyin serverni production flag’larsiz ishga tushiring:

```bash
licensectl init-state --config server.json --state /var/lib/ecochain-license/state.db
license-server --config server.json --state /var/lib/ecochain-license/state.db
```

## Majburiy fizik qabul sinovlari

- Yangi random challenge imzolanadi va `.lic` public key’i bilan tekshiriladi.
- Xuddi shu fayl boshqa fizik TPM’da ishlamaydi.
- Signing key’da password authorization fallback yo‘q.
- Agent yo‘qolsa yoki DMI o‘qilmasa lease berilmaydi.
- Operator nazoratida counter oshirilgach eski policy bilan **yangi session** ochib sign qilish rad etiladi.
- TPM clear yoki NV index’ni qayta yaratish eski ruxsatni tiklamaydi; bu platforma provisioning siyosati bilan alohida tekshiriladi.
- Disk backup’dan qaytarilgan SQLite TPM holatini ortga qaytarmaydi. Ammo software vaqt/revision state’ining rollback himoyasi bu fakt bilan avtomatik hal bo‘lmaydi.

## Deaktivatsiya va migratsiya

PolicyNV hisoblagichini oshirish eski kalit policy’sini yaroqsiz qiladi. Lekin oddiy "deactivated=true" fayli yoki imzolashdan oldin tayyorlangan bayonot bekor qilish isboti emas. Oldin berilgan lease’lar muddati tugaguncha lokal funksiyalarni ochishi mumkin.

Pinned trust va trusted-agent modelidagi implementatsiya qilingan migratsiya:

1. Vendor bir martalik challenge’ni license ID, old TPM identity va yangi server kalitiga bog‘laydi.
2. Agent siyosat bo‘yicha counter’ni oshiradi.
3. Oldindan ro‘yxatdan o‘tgan, ishonchli AK orqali `TPM2_NV_Certify` natijasi olinadi.
4. Vendor AK chain, fresh nonce, aniq NV Name, counter qiymati va oldingi enrollment’ni tekshiradi.
5. Yangi litsenziya 480 soniyalik kutish bilan chiqariladi: eski lease 180s + clock tolerance 300s. Revision oshadi, huquqlar va expiration saqlanadi. Qayta renewal kutish oynasini qisqartirmaydi.

**Proof verifier va atomik migration completion mavjud.** Oddiy issue ikkinchi binding’ni rad etadi; rebind faqat signed challenge, old/target proof va joriy revision orqali amalga oshadi. Eski server ishdan chiqqan va attestation olinmasa vendor bilan alohida recovery siyosati talab etiladi. NV proof barcha oldindan tayyorlangan policy session yoki patched agent’lar bekor bo‘lganini universal isbotlamaydi; agent yaxlitligi va TPM device kirishi himoyalanadi.

vTPM bilan birga klonlanadigan VM, root tomonidan patch qilingan verifier yoki TPM signing’ni tarmoq orqali relay qilishga qarshi to‘liq himoya bu adapter doirasidan tashqarida. Ishonchli platforma nazorati kerak.
