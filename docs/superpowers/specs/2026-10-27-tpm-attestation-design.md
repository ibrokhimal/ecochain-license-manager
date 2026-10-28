# TPM NV attestation va offline migration

## Maqsad va ishonch modeli
Mavjud License Manager’ga vendor tomonidan tekshiriladigan fresh TPM NV dalili va bir martalik server migratsiyasi qo‘shiladi. Customer tarmog‘i offline; fayllar administrator orqali yetkaziladi. Fizik TPM’ga buyruq avtomatik yuborilmaydi. Docker sinovi alohida swtpm state’da bajariladi.

TPM trust bootstrap: vendorning ishonchli provisioning operatori restricted AK public area + qualified Name, policy-only lease key public area, NV Name, activation counter, organization va host DMI’ni oldindan ro‘yxatga oladi. Untrusted client yuborgan AK public key o‘z-o‘zidan trust olmaydi. EK manufacturer CA / MakeCredential bootstrap bu bosqichda avtomatlashtirilmaydi; pinned trusted provisioning modeli ishlatiladi.

## Dalil
NV public area Name’i SHA-256 bilan qayta hisoblanadi; NV maydoni initialized 8-byte counter ekanligi tekshiriladi. Oddiy yoziladigan NV xotira counter o‘rniga qabul qilinmaydi.
Faqat ECC P-256 / SHA-256 public area qo‘llanadi. AK fixedTPM+fixedParent+sensitiveDataOrigin+restricted+sign, decrypt emas. Device key fixedTPM+fixedParent+sensitiveDataOrigin+sign, restricted/decrypt/userWithAuth emas. Device authPolicy aynan SHA-256 PolicyNV equality (offset=0, 8-byte counter, pinned NV Name) bo‘lishi kerak.

TPMS_ATTEST bounded big-endian parser: magic=0xff544347, type=TPM_ST_ATTEST_NV=0x8014, pinned AK qualifiedSigner, fresh extraData, clockInfo.safe=1, pinned NV indexName, offset=0, 8-byte unsigned contents, no trailing bytes. Signature ECDSA P-256 DER over original attestation bytes. Unsupported algorithms, names, lengths and types fail closed.

## Workflow
1. Vendor trust-import qiladi: physical record explicit approved onboarding; simulator record faqat --allow-simulator bilan.
2. Enrollment challenge vendor Ed25519 bilan alohida domain’da imzolanadi va SQLite’da saqlanadi. U activation request digest, license id, trusted device record va 24h muddatga bog‘lanadi.
3. Host tpm2_nvcertify orqali challenge’ga bog‘langan NV proof chiqaradi. Rust verifier baseline counter’ni tekshiradi.
4. Complete-enrollment trust, request proof, hardware and public key binding, NV proof, one-time challenge’ni bir SQLite transaction’da tekshirib license chiqaradi. Simulator faqat development binding chiqaradi; production default rad etadi.
5. Migration challenge amaldagi old license revision/digest va yangi target request/trust record’ga bog‘lanadi. Old va target proof nonce’lari role-domain bilan ajratiladi.
6. Operator eski trusted agentni to‘xtatadi, hisoblagichni oshiradi; fresh-session sign endi ishlamaydi. Old proof counter>baseline, target proof counter==baseline bo‘lishi kerak.
7. Complete-migration eski revision o‘zgarmaganini tekshiradi, faqat target hardware/key’ni almashtiradi, revision+1 qiladi, entitlement/expiration’ni oshirmaydi. not_before=vendor_now+480s: 180s lease + 300s clock tolerance. Expiration kutish oynasidan oldin tugasa migratsiya rad etiladi.
8. Registry update va challenge consume atomik. Xuddi shu completion input’i retry qilinsa ayni envelope qaytadi; boshqa input yoki stale challenge rad etiladi. Bir license uchun bir nechta pending challenge mumkin, ammo birinchi completion revision’ni o‘zgartirib qolganini yaroqsiz qiladi.

## Chegaralar
Trust record’ni o‘zgartirish/registry rollback vendor operatori ishonchiga bog‘liq. Root tomonidan patch qilingan agent, TPM relay, klonlanadigan vTPM va oldindan tayyorlangan policy session’lar ustidan mutlaq adversarial revocation da’vo qilinmaydi. Trusted agent har sign uchun fresh session yaratadi; physical acceptance’da TPM device ruxsatlari va agent integrity tekshiriladi. NV proof joriy counter’ni tasdiqlaydi; barcha mumkin bo‘lgan key-use yo‘llari yo‘qolganini universal isbotlamaydi.

## Moslik
Mavjud development issue/21 test saqlanadi. TPM uchun eski --approve-tpm-enrollment boolean fresh proof o‘rniga ishlamaydi; CLI yangi workflow’ga yo‘naltiradi. Existing manual legacy TPM license avtomatik migratsiya qilinmaydi: avval attested enrollment record kerak. Vendor registry’ga yangi jadvallar qo‘shiladi; server lease DB sxemasi o‘zgarmaydi.
