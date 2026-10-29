# Fizik Linux deployment shablonlari

Bu fayllar hostga avtomatik o‘rnatilmagan. [TPM workflow](../docs/TPM_WORKFLOW.md)ni va servis hardening’ini xavfsizlik operatori tekshiradi.

1. Linux binary’larini `/usr/local/bin/`ga, root-owned konfiguratsiyani `/etc/ecochain-license-tpm/`ga o‘rnating.
2. `license-tpm` servis guruhini yarating. systemd unit root UID’da faqat DMI va TPM o‘qish/sign uchun ishlaydi; capability yo‘q, tizim fayllari read-only. `SupplementaryGroups=tss` Ubuntu’dagi `/dev/tpmrm0` uchun fayl ruxsatini beradi: `DeviceAllow` o‘zi bu ruxsatni bermaydi. Boshqa distributivda TPM device guruhini tekshiring. Site DMI/TPM ACL tayyorlasa dedicated user’ga almashtirish mumkin.
3. Unit’ni systemd katalogiga joylang, daemon-reload qiling va agentni ishga tushiring. Agentning PATH’ida ishonchli `tpm2-tools` bo‘lsin. Skript/servis boshqa TPM ilovalari bilan birga tekshiriladi.
4. Konteyner config’da `device={"kind":"tpm2","socket":"/run/host-license/agent.sock"}` bo‘ladi. Org/product, `.lic`, vendor pubkey, lokal CA/server cert va caller token hash’larini tayyorlang.
5. Config’ga server UID/GID uchun read, state’ga write huquqi bering; agent socket guruhi GID’ni `TPM_AGENT_GID` sifatida kiriting. Vendor private key server config katalogida bo‘lmaydi.
6. `not_before` kelgach explicit init-state qiling; oddiy server startup state yo‘qolganda uni yangidan yaratmaydi. Init CLI’ni konteynerda shu config/state/socket mount’lar va guruh bilan bir martalik ishga tushirish mumkin.
7. `docker compose -f deploy/compose.tpm.yaml up -d` orqali ishga tushiring. Bu konfiguratsiyada development flag yo‘q.

Default port faqat loopback’da. LAN klientlari uchun `LICENSE_BIND_IP`ni serverning aniq LAN IP’siga o‘zgartiring, TLS server SAN/DNS va firewall’ni moslang. mTLS talabini olib tashlamang. Offline egress host/router firewall siyosatidir.

2026-10-29: Ubuntu 24.04 x86_64 fizik TPM 2.0’da provisioning, systemd agent, activation request, NV proof va vendor issuance tekshirildi. Production Compose bilan `binding_mode=tpm2`, 9 ta mTLS/gRPC smoke tekshiruvi va konteyner restartidan keyingi holat saqlanishi o‘tdi. Ikkinchi fizik hostga migratsiya, host reboot va to‘liq production acceptance hali bajarilmagan. Docker Desktop host TPM’ini ifodalamaydi. Provisioning va NV increment kabi qaytarib bo‘lmaydigan buyruqlar deploy start tomonidan avtomatik bajarilmaydi.
