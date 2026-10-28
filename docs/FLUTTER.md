# Flutter / GetX integratsiyasi

Bu papkada mavjud Flutter ilovasi yo‘q. Shu sababli bu hujjat integratsiya kontrakti; Flutter build ishlatilgani da’vo qilinmaydi.

## Oqim
1. Lokal CA, klient sertifikat/private key va foydalanuvchi tokenini OS secure storage yoki korporativ provisioning orqali oling. Tokenni Dart source yoki assets ichiga yozmang.
2. Rust `rpc::connect` orqali mTLS kanal yaratadi; server DNS nomi sertifikat SAN bilan tekshiriladi.
3. Login’da yangi session UUID yarating. `Acquire` uchun `unix_seconds:UUID` formatida request ID saqlang (`clock::request_id()`); tarmoq timeout bo‘lsa aynan o‘sha request id bilan retry qiling. Retry oynasi 1 soat, undan eski ID rad etiladi. Sessiya ID’ni litsenziya revision’i almashganda saqlang va yangi request ID bilan Acquire qiling.
4. Lease kelganda signed token va server vaqti Rust sessiyasida saqlanadi. Heartbeat 60s, jitter ±10s; ilova background’dan qaytganda darhol tekshiriladi.
5. `Renew` uchun har bir yangi heartbeat’da yangi request id, ayni retry uchun o‘sha id ishlatiladi. RPC deadline 3s. Backoff 1, 2, 4, 8, 15s; lease deadline’dan keyin ruxsat uzaytirilmaydi.
6. `Validate` tokenning o‘zi bilan birga amaldagi autentifikatsiya kontekstini ham tekshiradi. Backend har bir himoyalangan operatsiyada shu tekshiruvni chaqirishi kerak.
7. GetX controller faqat Rust holatini UI’ga aks ettiradi: active, unreachable, expired, denied. Route guard xavfsizlik chegarasi emas.

## flutter_rust_bridge chegarasi
Mavjud ilovangizga Rust kutubxonasini path dependency sifatida ulang; `rpc::connect`, `license::verify`, `lease::verify_token` funksiyalarini bridge wrapper ichida chaqiring. FRB versiyasi mavjud ilova bilan bir xil bo‘lishi kerak; bu standalone server paketi majburiy FRB dependency kiritmaydi.

Bridge uchun tavsiya etilgan ommaviy DTO va funksiyalar:

```rust,ignore
enum UiLicenseState { Active, Unreachable, Expired, Denied }
async fn acquire_license(session_id: String, modules: Vec<String>) -> Result<()>;
async fn renew_license() -> Result<()>;
async fn require_module(module: String) -> Result<()>;
fn license_state_stream(sink: StreamSink<UiLicenseState>);
```

`require_module` lokal hisoblashdan avval lease imzosi, organization, modul va vaqtni Rust ichida tekshiradi. Rust sessiyasi monotonic deadline saqlaydi. Diskda saqlangan eski lease restartda yangi TTL olmaydi; fresh server validation talab qiling. Ilova backendga yuboradigan operatsiyalarda esa backenddagi Validate tekshiruvi majburiy.

`max_users` noyob autentifikatsiyalangan subject bo‘yicha. Demo’da alice va bob tokenlari alohida foydalanuvchilarni ifodalaydi; production’da token berish/revoke qilish korporativ identity tizimi bilan integratsiya qilinadi.

## Sertifikat yangilash
TLS sertifikati muddati litsenziya muddatidan alohida. Offline CA va klient sertifikatlarini muddati tugashidan oldin lokal administrator orqali yangilang. TLS tekshiruvini o‘chirish bilan muammoni chetlab o‘tmang.
