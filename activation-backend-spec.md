# Nebula Activation Server — Architecture Specification
## Version 1.0 | Lifetime License System

---

## Overview

This document specifies the complete backend required to support the Nebula frontend activation system. The backend is a small, stateless REST API. No subscription billing, no recurring jobs — lifetime keys only.

**Language recommendation:** Node.js (Express) or Python (FastAPI). The spec is language-agnostic.

---

## Technology Stack

| Component       | Recommendation                        |
|-----------------|---------------------------------------|
| Runtime         | Node.js 20 LTS / Python 3.11          |
| Framework       | Express 4 / FastAPI                   |
| Database        | PostgreSQL (primary) or SQLite (solo) |
| Signing         | RS256 JWT (jsonwebtoken / python-jose)|
| Rate limiting   | express-rate-limit / slowapi          |
| Hosting         | Railway / Render / Fly.io             |

---

## Database Schema

```sql
-- License keys table
CREATE TABLE license_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash      TEXT UNIQUE NOT NULL,      -- SHA-256 of the raw key (never store plaintext)
  plan          TEXT NOT NULL DEFAULT 'lifetime',
  max_devices   INTEGER NOT NULL DEFAULT 2,
  is_revoked    BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at    TIMESTAMPTZ,
  revoked_reason TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  customer_email TEXT                       -- optional, for support lookups
);

-- Device activations table
CREATE TABLE device_activations (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_key_id    UUID NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
  device_fingerprint TEXT NOT NULL,         -- the hash from the frontend
  activated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_agent        TEXT,
  UNIQUE(license_key_id, device_fingerprint)
);

CREATE INDEX idx_device_fp ON device_activations(device_fingerprint);
CREATE INDEX idx_key_hash   ON license_keys(key_hash);
```

---

## Cryptographic Key Setup

```bash
# Generate RSA key pair (run once on server setup)
openssl genrsa -out private.pem 2048
openssl rsa    -in private.pem -pubout -out public.pem

# Store private.pem as an environment variable (NEVER commit to git):
export NEBULA_PRIVATE_KEY="$(cat private.pem)"

# Put the contents of public.pem into nebula-activation.js → NEBULA_CONFIG.PUBLIC_KEY_PEM
```

**Rule:** `private.pem` never touches frontend code, git repositories, or client-side storage. Only the public key is embedded in the frontend.

---

## API Endpoints

### POST /v1/license/activate

Validates a license key, binds a device, and returns a signed JWT.

**Request body:**
```json
{
  "licenseKey": "ABCD-1234-EFGH-5678",
  "deviceFingerprint": "a1b2c3d4",
  "appVersion": "1.0"
}
```

**Logic:**
1. Hash the incoming key: `keyHash = SHA256(licenseKey.toUpperCase())`
2. Look up `keyHash` in `license_keys`
3. If not found → 404 `KEY_NOT_FOUND`
4. If `is_revoked = TRUE` → 403 `KEY_REVOKED`
5. Count rows in `device_activations` for this key
6. If count >= `max_devices` AND this fingerprint is NOT already registered → 403 `KEY_ALREADY_USED`
7. If this fingerprint IS already registered → update `last_seen_at`, re-issue token → 200
8. Insert new device row
9. Sign JWT with RS256 private key:
   ```json
   {
     "sub": "<license_key_id>",
     "deviceFingerprint": "<fingerprint>",
     "plan": "lifetime",
     "iat": <unix_timestamp>,
     "iss": "nebula-activation-v1"
   }
   ```
   Note: No `exp` claim for lifetime keys (never expires by itself).
10. Return token + device count

**Success response (200):**
```json
{
  "token": "<jwt>",
  "deviceCount": 1,
  "plan": "lifetime"
}
```

**Error response (4xx):**
```json
{
  "error": "KEY_ALREADY_USED",
  "message": "This key has reached its device limit."
}
```

---

### POST /v1/license/revalidate

Called by the frontend silently every 24 hours. Confirms the token is still valid.

**Request body:**
```json
{
  "token": "<jwt>",
  "deviceFingerprint": "a1b2c3d4"
}
```

**Logic:**
1. Verify JWT signature with public key
2. Decode `sub` (license_key_id) from payload
3. Check `license_keys` row: not revoked
4. Check `device_activations`: this fingerprint is still registered
5. Update `last_seen_at`
6. Optionally rotate the token (recommended every 7 days)

**Success response (200):**
```json
{
  "valid": true,
  "newToken": "<rotated_jwt_or_null>"
}
```

**Failure response (200 with valid: false):**
```json
{
  "valid": false,
  "reason": "KEY_REVOKED"
}
```

---

### POST /v1/license/revoke-device

User-initiated deactivation. Frees the device slot.

**Request body:**
```json
{
  "token": "<jwt>",
  "deviceFingerprint": "a1b2c3d4"
}
```

**Logic:**
1. Verify JWT signature
2. Delete the matching `device_activations` row

**Response (200):**
```json
{ "success": true }
```

---

## License Key Generation

Generate keys offline (before distribution) and insert their hashes into the database.

```javascript
// Node.js key generation script (run once per batch, server-side only)
const crypto = require('crypto');

function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous chars (0/O, 1/I/L)
  let key = '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) key += '-';
    key += chars[Math.floor(Math.random() * chars.length)];
  }
  return key; // e.g. "A3BX-9KMN-2QWZ-7VPT"
}

function hashKey(key) {
  return crypto.createHash('sha256').update(key.toUpperCase()).digest('hex');
}

// Insert into DB
const key = generateLicenseKey();
const hash = hashKey(key);
// INSERT INTO license_keys (key_hash, plan, max_devices) VALUES (hash, 'lifetime', 2);
// Send `key` to customer — never store the plaintext key in the DB.
console.log('Key:', key);
```

---

## Rate Limiting

Apply these limits on the activation endpoints to prevent brute-force enumeration:

| Endpoint      | Limit                     |
|---------------|---------------------------|
| `/activate`   | 5 requests / 15 min / IP  |
| `/revalidate` | 20 requests / hour / IP   |
| `/revoke-device` | 10 requests / hour / IP |

---

## Security Checklist

- [ ] Private key stored as environment variable (not in code or git)
- [ ] All endpoints served over HTTPS only
- [ ] Rate limiting active on all activation endpoints
- [ ] `key_hash` stored in DB (never plaintext key)
- [ ] JWT `iss` claim validated on revalidation
- [ ] Device fingerprint bound in JWT payload
- [ ] CORS restricted to your app's domain
- [ ] PostgreSQL connection uses SSL in production
- [ ] `device_activations.last_seen_at` monitored for anomalies (many IPs same key)

---

## Admin Operations

**Revoke a license:**
```sql
UPDATE license_keys SET is_revoked = TRUE, revoked_at = NOW() WHERE key_hash = SHA256('ABCD-1234-EFGH-5678');
```
After the next revalidation (≤24h), the frontend will stop working.

**Check active devices for a key:**
```sql
SELECT da.device_fingerprint, da.activated_at, da.last_seen_at, da.user_agent
FROM device_activations da
JOIN license_keys lk ON lk.id = da.license_key_id
WHERE lk.key_hash = SHA256('ABCD-1234-EFGH-5678');
```

**Free a device slot (for a customer who got a new phone):**
```sql
DELETE FROM device_activations WHERE device_fingerprint = '<fp>';
```

---

## Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/nebula_licensing
NEBULA_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
JWT_ISSUER=nebula-activation-v1

# Optional
PORT=3000
NODE_ENV=production
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=5
```

---

*This spec was generated to accompany the Nebula frontend activation system (nebula-activation.js). Keep this document server-side only.*
