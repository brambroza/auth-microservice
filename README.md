# auth-microservice

Auth กลางสำหรับทุกระบบของ GO Along: login ครั้งเดียวได้ JWT ที่ระบบอื่น (.NET, Node, Go, React Native) ตรวจเองได้ด้วย public key โดยไม่ต้องเรียก service นี้ทุก request

เขียนด้วย Go + PostgreSQL ได้ binary เดียว ขนาดประมาณ 16 MB

## สิ่งที่ทำได้ในเวอร์ชันนี้

- Login ด้วย email + password (argon2id)
- Access token เป็น JWT เซ็นด้วย ES256 พร้อม JWKS endpoint และหมุน signing key ได้โดยไม่หยุดระบบ
- Refresh token แบบหมุนทุกครั้งที่ใช้ ถ้า token เก่าถูกนำมาใช้ซ้ำ session นั้นถูกยกเลิกทันที
- 2FA ด้วย TOTP (Google/Microsoft Authenticator) กันการใช้รหัสซ้ำ และมี recovery code 10 ชุด
- Multi-tenant: ผู้ใช้หนึ่งคนอยู่ได้หลายบริษัท มี role แยกตามระบบ เช่น `wms:admin`
- บังคับ 2FA ระดับ tenant (`require_mfa`)
- กัน brute force: ล็อกบัญชีเมื่อใส่รหัสผิดเกินกำหนด และ rate limit ต่อ IP
- Audit log ทุกเหตุการณ์ด้านความปลอดภัย
- Admin API: สร้าง tenant, ผู้ใช้, กำหนด role, reset 2FA, บังคับ logout

## สิ่งที่ยังไม่มี

| รายการ | หมายเหตุ |
|---|---|
| Passkey / biometric (WebAuthn) | ตาราง `mfa_factors` รองรับ type `webauthn` แล้ว ยังไม่มี endpoint |
| หน้า login กลางแบบ SSO (Authorization Code + PKCE) | ตอนนี้แต่ละระบบเรียก `/v1/auth/login` เองจากหน้า login ของตัวเอง |
| LINE Login, Google, Microsoft | |
| ลืมรหัสผ่านผ่าน email, OTP ผ่าน LINE/email | |
| Step-up authentication | ระบบปลายทางตรวจ `amr` และ `auth_time` เองได้แล้ว แต่ยังไม่มี endpoint ยืนยันซ้ำ |

## เริ่มใช้งาน

```bash
cp .env.example .env
echo "AUTH_MASTER_KEY=$(openssl rand -base64 32)" >> .env

docker compose up -d --build

# สร้าง platform admin คนแรก (ถามรหัสผ่านทาง stdin)
docker compose run --rm auth create-admin -email you@example.com
```

รันโดยไม่ใช้ Docker:

```bash
set -a; source .env; set +a
go run ./cmd/authd                 # รัน server (migrate ให้อัตโนมัติ)
go run ./cmd/authd create-admin -email you@example.com
go run ./cmd/authd rotate-key      # เพิ่ม signing key ใหม่
```

`AUTH_MASTER_KEY` ใช้เข้ารหัส signing key และ TOTP secret ในฐานข้อมูล ต้องสำรองไว้ ถ้าหายจะอ่านข้อมูลเหล่านั้นไม่ได้ และทุก instance ต้องใช้ค่าเดียวกัน

## ขั้นตอน login

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Auth
    C->>A: POST /v1/auth/login (email, password, tenant?)
    alt ไม่ได้เปิด 2FA
        A-->>C: access_token + refresh_token
    else เปิด 2FA
        A-->>C: mfa_required + mfa_token (อายุ 5 นาที)
        C->>A: POST /v1/auth/mfa/verify (mfa_token, code)
        A-->>C: access_token + refresh_token
    end
    Note over C,A: access token หมดอายุใน 10 นาที
    C->>A: POST /v1/auth/refresh (refresh_token)
    A-->>C: access_token ใหม่ + refresh_token ใหม่
```

รหัสผ่านถูกแล้วแต่ยังไม่ผ่านปัจจัยที่สองจะไม่ได้ token ใด ๆ และ `mfa_token` หนึ่งตัวลองรหัสได้ 5 ครั้ง

## API

| Method | Path | ต้องมี token | ทำอะไร |
|---|---|---|---|
| POST | `/v1/auth/login` | | login |
| POST | `/v1/auth/mfa/verify` | | ยืนยันปัจจัยที่สอง (`method`: `totp` หรือ `recovery_code`) |
| POST | `/v1/auth/refresh` | | ขอ token ชุดใหม่ |
| POST | `/v1/auth/logout` | | ยกเลิก session ของ refresh token นั้น |
| POST | `/v1/auth/switch-tenant` | ✓ | เปลี่ยนบริษัทใน session เดิม |
| POST | `/v1/auth/password` | ✓ | เปลี่ยนรหัสผ่าน (อุปกรณ์อื่นถูก logout) |
| GET | `/v1/me` | ✓ | ข้อมูลผู้ใช้, tenant, สถานะ 2FA |
| POST | `/v1/mfa/totp/enroll` | ✓ | เริ่มเปิด 2FA ได้ `secret` และ `otpauth_url` สำหรับทำ QR |
| POST | `/v1/mfa/totp/activate` | ✓ | ยืนยันรหัสแรก ได้ recovery codes (แสดงครั้งเดียว) |
| POST | `/v1/mfa/totp/disable` | ✓ | ปิด 2FA ต้องใส่รหัสผ่านและรหัสปัจจุบัน |
| POST | `/v1/mfa/recovery-codes` | ✓ | ออก recovery codes ชุดใหม่ |
| POST | `/v1/admin/tenants` | admin | สร้าง tenant |
| POST | `/v1/admin/users` | admin | สร้างผู้ใช้ |
| POST, DELETE | `/v1/admin/memberships` | admin | เพิ่ม/ลบ role (`user_id`, `tenant`, `app`, `role`) |
| POST | `/v1/admin/users/{id}/mfa/reset` | admin | ลบ 2FA ของผู้ใช้ (กรณีมือถือหาย) และ logout ทุกอุปกรณ์ |
| POST | `/v1/admin/users/{id}/revoke-sessions` | admin | บังคับ logout ทุกอุปกรณ์ |
| GET | `/.well-known/jwks.json` | | public key สำหรับตรวจ token |
| GET | `/.well-known/openid-configuration` | | issuer และตำแหน่ง JWKS |
| GET | `/healthz` | | ตรวจสถานะ |

Error ทุกตัวตอบรูปแบบเดียวกัน: `{"error": "invalid_credentials", "message": "..."}`

ตัวอย่าง:

```bash
curl -s localhost:8080/v1/auth/login \
  -d '{"email":"you@example.com","password":"...","tenant":"acme"}'
```

## Claim ใน access token

```json
{
  "iss": "https://auth.example.com",
  "aud": ["goalong"],
  "sub": "5358d2df-…",
  "email": "you@example.com",
  "tenant_id": "9396f958-…",
  "tenant": "acme",
  "roles": ["hrm:viewer", "wms:admin"],
  "amr": ["pwd", "otp", "mfa"],
  "auth_time": 1794899567,
  "sid": "…",
  "exp": 1794900167
}
```

- `amr` บอกวิธีที่ใช้ login: `pwd` รหัสผ่าน, `otp` TOTP, `rc` recovery code, `mfa` ผ่านสองปัจจัยแล้ว
- ระบบปลายทางที่มีรายการสำคัญควรตรวจว่า `amr` มี `mfa` และ `auth_time` ไม่เก่าเกินไป
- ถ้า tenant บังคับ 2FA แต่ผู้ใช้ยังไม่เปิด token จะมี `mfa_enrollment_required: true` และ `roles` ว่าง จนกว่าจะเปิด 2FA แล้ว refresh

## ต่อจากระบบอื่น

ระบบปลายทางตรวจ 4 อย่าง: ลายเซ็น (ES256 จาก JWKS), `iss`, `aud`, `exp` แล้วอ่าน `tenant_id` กับ `roles` ไปใช้ ให้ cache JWKS และโหลดใหม่เมื่อเจอ `kid` ที่ไม่รู้จัก

ASP.NET Core:

```csharp
builder.Services.AddAuthentication("Bearer").AddJwtBearer(o =>
{
    o.Authority = "https://auth.example.com";   // ต้องตรงกับ AUTH_ISSUER
    o.Audience = "goalong";
    o.MapInboundClaims = false;
});
```

Node.js (`jose`):

```js
import { createRemoteJWKSet, jwtVerify } from "jose";
const jwks = createRemoteJWKSet(new URL("https://auth.example.com/.well-known/jwks.json"));
const { payload } = await jwtVerify(token, jwks, {
  issuer: "https://auth.example.com", audience: "goalong", algorithms: ["ES256"],
});
```

## ข้อควรรู้ก่อนขึ้น production

- **ต้องอยู่หลัง HTTPS เสมอ** service นี้ไม่ทำ TLS เอง
- **Logout ไม่ได้ทำให้ access token ที่ออกไปแล้วใช้ไม่ได้ทันทีในระบบอื่น** token ยังผ่านการตรวจจนหมดอายุ (ค่าเริ่มต้น 10 นาที) ถ้าต้องการสั้นกว่านี้ให้ลด `AUTH_ACCESS_TTL`
- **Rate limit เก็บใน memory ของแต่ละ instance** รัน 2 instance เพดานจริงจะเป็น 2 เท่า ส่วนการล็อกบัญชีเก็บใน DB จึงมีผลทุก instance
- **Refresh พร้อมกันหลาย request จะทำให้ session ถูกยกเลิก** เพราะถือเป็นการใช้ token ซ้ำ ฝั่ง client ต้องให้มี refresh ทำงานทีละตัว
- **`AUTH_TRUST_PROXY=true`** เปิดเฉพาะเมื่อเข้าถึง service ได้ผ่าน gateway ของตัวเองเท่านั้น มิฉะนั้น client ปลอม IP ได้
- **PgBouncer แบบ transaction mode**: เพิ่ม `default_query_exec_mode=exec` ใน `AUTH_DATABASE_URL` หรือเปิด `max_prepared_statements` ที่ PgBouncer
- ข้อความ error ตอน login ไม่บอกว่า email มีอยู่หรือไม่ ยกเว้นกรณีบัญชีถูกล็อก ซึ่งตอบ `account_locked`

## ทดสอบ

Integration test ต้องใช้ PostgreSQL จริง แต่ละ test สร้าง schema ชั่วคราวของตัวเอง

```bash
TEST_DATABASE_URL=postgres://auth:auth@localhost:5432/auth go test -race ./...
```

ถ้าไม่ตั้ง `TEST_DATABASE_URL` จะรันเฉพาะ unit test

## โครงสร้าง

```
cmd/authd            จุดเริ่มโปรแกรมและคำสั่งย่อย
internal/api         HTTP handler, middleware, rate limit
internal/store       SQL ทั้งหมด
internal/db          connection pool และ migration (SQL ฝังใน binary)
internal/token       ออกและตรวจ JWT, JWKS
internal/totp        TOTP ตาม RFC 6238
internal/password    argon2id
internal/secret      เข้ารหัสข้อมูลใน DB, สุ่มและ hash token
```
