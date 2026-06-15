/**
 * api/verify.js
 * ─────────────────────────────────────────────────────────────────
 * Vercel Serverless Function — Nebula License System
 *
 * Single endpoint that handles three distinct actions:
 *   • activate   — validate key, register device, issue JWT
 *   • revalidate — verify existing token, optionally rotate
 *   • revoke     — deregister a device (user-initiated sign-out)
 *
 * POST /api/verify
 * Body must always include: { action: 'activate' | 'revalidate' | 'revoke', ... }
 *
 * Required Vercel environment variables:
 *   JWT_SECRET           — 64-char hex string (no spaces, no quotes)
 *   SUPABASE_URL         — https://xxxx.supabase.co
 *   SUPABASE_SERVICE_KEY — service_role key (NOT the anon key)
 * ─────────────────────────────────────────────────────────────────
 */

'use strict';

// ─── All requires hoisted to module top-level (never inline) ─────────────────
const jwt    = require('jsonwebtoken');
const https  = require('https');
const crypto = require('crypto');

/* ══════════════════════════════════════════════════════════════
   SECTION 1 — CONFIG
   .trim() every env var to strip invisible dashboard whitespace.
══════════════════════════════════════════════════════════════ */
const JWT_SECRET           = (process.env.JWT_SECRET           || '').trim();
const SUPABASE_URL         = (process.env.SUPABASE_URL         || '').trim().replace(/\/$/, '');
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

const JWT_ALGORITHM      = 'HS256';
const JWT_EXPIRES_IN     = '30d';   // used for revalidate rotations; activate issues non-expiring tokens
const MAX_PAYLOAD_BYTES  = 8192;

// CHANGED: Accept any alphanumeric key between 10 and 64 characters (hyphens are stripped before this check).
const LICENSE_KEY_REGEX = /^[A-Z0-9]{10,64}$/;

// Only these origins receive permissive CORS headers
const ALLOWED_ORIGINS = [
  'https://nepulahabits.vercel.app'
];

/* ══════════════════════════════════════════════════════════════
   SECTION 2 — UTILITIES
══════════════════════════════════════════════════════════════ */

/** Stream and JSON-parse the request body safely. */
function readBody(req) {
  return new Promise(function (resolve, reject) {
    // Framework (Next.js / Express) may pre-parse; use it if available.
    if (req.body && typeof req.body === 'object') {
      return resolve(req.body);
    }
    var raw = '';
    req.setEncoding('utf8');
    req.on('data', function (chunk) {
      raw += chunk;
      if (raw.length > MAX_PAYLOAD_BYTES) {
        reject(new Error('payload_too_large'));
      }
    });
    req.on('end', function () {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch (e) { reject(new Error('invalid_json')); }
    });
    req.on('error', reject);
  });
}

/** Minimal Supabase PostgREST REST client — no SDK required. */
function supabaseFetch(path, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var bodyStr = opts.body ? JSON.stringify(opts.body) : null;
    var method  = opts.method || 'GET';
    var url     = new URL(SUPABASE_URL + path);

    var reqOpts = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   method,
      headers: {
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': 'Bearer ' + SUPABASE_SERVICE_KEY,
        'Content-Type':  'application/json',
        'Prefer':        'return=representation'
      }
    };
    if (bodyStr) {
      reqOpts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }

    var req = https.request(reqOpts, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        try {
          var parsed = JSON.parse(Buffer.concat(chunks).toString());
          if (res.statusCode >= 400) {
            resolve({ data: null, error: parsed.message || parsed.error || 'db_error' });
          } else {
            resolve({ data: parsed, error: null });
          }
        } catch (e) {
          resolve({ data: null, error: 'json_parse_error' });
        }
      });
    });
    req.on('error', function () { resolve({ data: null, error: 'network_error' }); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/** Build CORS headers, restricting to known origins. */
function corsHeaders(req) {
  var origin  = (req.headers && req.headers.origin) || '';
  var allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary':                         'Origin'
  };
}

/**
 * Validate a device fingerprint.
 * Accepts hex strings of 1–64 chars (covers FNV-1a 32-bit output which
 * is a variable-length hex string, never longer than 8 chars, as well as
 * SHA-256 outputs up to 64 chars from future fingerprint upgrades).
 */
function isValidFingerprint(fp) {
  return typeof fp === 'string' && /^[a-f0-9]{1,64}$/.test(fp) && fp.length >= 1;
}

/** Send a JSON response with given status code and body. */
function json(res, status, headers, body) {
  res.writeHead(status, Object.assign({}, headers, { 'Content-Type': 'application/json' }));
  res.end(JSON.stringify(body));
}

/* ══════════════════════════════════════════════════════════════
   SECTION 3 — ACTION HANDLERS
══════════════════════════════════════════════════════════════ */

/**
 * ACTION: activate
 * ────────────────
 * Body: { action, licenseKey, deviceFingerprint, appVersion? }
 *
 * 1. Strip hyphens from key, validate format
 * 2. Look up key in Supabase
 * 3. Check revocation / device limit (expires_at is intentionally ignored)
 * 4. Register device (if new)
 * 5. Sign and return a non-expiring JWT
 *
 * DB columns used: key, plan, max_devices, revoked, activated_devices
 * expires_at is fetched but deliberately ignored — keys are permanent until
 * manually revoked via the `revoked` boolean in the database.
 */
async function handleActivate(body, cors, res) {
  // CHANGED: strip hyphens before normalising and validating
  var licenseKey        = ((body.licenseKey        || '') + '').trim().toUpperCase().replace(/-/g, '');
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();

  if (!LICENSE_KEY_REGEX.test(licenseKey)) {
    return json(res, 400, cors, { error: 'INVALID_KEY_FORMAT' });
  }
  if (!isValidFingerprint(deviceFingerprint)) {
    return json(res, 400, cors, { error: 'INVALID_FINGERPRINT' });
  }

  // Fetch key record from Supabase
  // Selecting only the columns we actually use; expires_at is omitted intentionally.
  var dbResult = await supabaseFetch(
    '/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) +
    '&select=id,key,plan,max_devices,revoked,activated_devices&limit=1'
  );

  if (dbResult.error) {
    console.error('[Nebula:activate] DB lookup error:', dbResult.error);
    return json(res, 503, cors, { error: 'DB_UNAVAILABLE' });
  }

  var rows = dbResult.data;
  if (!rows || rows.length === 0) {
    return json(res, 404, cors, { error: 'KEY_NOT_FOUND' });
  }

  var keyRecord = rows[0];

  if (keyRecord.revoked) {
    return json(res, 403, cors, { error: 'KEY_REVOKED' });
  }
  // CHANGED: expires_at check removed entirely — keys are treated as permanent.

  // Device management
  var activatedDevices        = Array.isArray(keyRecord.activated_devices)
                                  ? keyRecord.activated_devices : [];
  var deviceAlreadyRegistered = activatedDevices.includes(deviceFingerprint);

  if (!deviceAlreadyRegistered) {
    var maxDevices = keyRecord.max_devices || 2;
    if (activatedDevices.length >= maxDevices) {
      return json(res, 403, cors, {
        error: 'KEY_ALREADY_USED',
        deviceCount: activatedDevices.length,
        maxDevices: maxDevices
      });
    }

    var updatedDevices = activatedDevices.concat(deviceFingerprint);
    var updateResult   = await supabaseFetch(
      '/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id),
      { method: 'PATCH', body: { activated_devices: updatedDevices } }
    );
    if (updateResult.error) {
      // Non-fatal: log and continue — token is still issued
      console.warn('[Nebula:activate] Device registration warning:', updateResult.error);
    }
  }

  // CHANGED: Sign a non-expiring JWT — no expiresIn option, no expires_at TTL cap.
  var jwtPayload = {
    sub:               licenseKey,
    plan:              keyRecord.plan || 'pro',
    deviceFingerprint: deviceFingerprint,
    jti:               crypto.randomBytes(16).toString('hex')
  };

  var token;
  try {
    token = jwt.sign(jwtPayload, JWT_SECRET, { algorithm: JWT_ALGORITHM });
  } catch (e) {
    console.error('[Nebula:activate] JWT sign error:', e.message);
    return json(res, 500, cors, { error: 'TOKEN_SIGN_ERROR' });
  }

  return json(res, 200, cors, {
    token:       token,
    plan:        keyRecord.plan || 'pro',
    deviceCount: (deviceAlreadyRegistered ? activatedDevices : activatedDevices.concat(deviceFingerprint)).length
  });
}

/**
 * ACTION: revalidate
 * ──────────────────
 * Body: { action, token, deviceFingerprint }
 *
 * 1. Verify JWT signature and expiry
 * 2. Check key is still active in DB (not revoked/expired)
 * 3. Optionally rotate token (new jti, same claims)
 * 4. Return { valid: true, newToken? }
 */
async function handleRevalidate(body, cors, res) {
  var token             = ((body.token             || '') + '').trim();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();

  if (!token) {
    return json(res, 400, cors, { error: 'MISSING_TOKEN' });
  }
  if (!isValidFingerprint(deviceFingerprint)) {
    return json(res, 400, cors, { error: 'INVALID_FINGERPRINT' });
  }

  // Verify JWT
  var payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
  } catch (e) {
    return json(res, 401, cors, { valid: false, error: 'TOKEN_INVALID' });
  }

  // Device binding check
  if (payload.deviceFingerprint && payload.deviceFingerprint !== deviceFingerprint) {
    return json(res, 403, cors, { valid: false, error: 'DEVICE_MISMATCH' });
  }

  var licenseKey = payload.sub;

  // Re-check key status in DB
  var dbResult = await supabaseFetch(
    '/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=revoked,expires_at,plan&limit=1'
  );

  if (dbResult.error || !dbResult.data || dbResult.data.length === 0) {
    console.warn('[Nebula:revalidate] Key lookup failed:', dbResult.error);
    // If DB is temporarily unavailable, trust the JWT (grace period applies client-side)
    return json(res, 200, cors, { valid: true });
  }

  var keyRecord = dbResult.data[0];

  if (keyRecord.revoked) {
    return json(res, 403, cors, { valid: false, error: 'KEY_REVOKED' });
  }
  if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
    return json(res, 403, cors, { valid: false, error: 'KEY_EXPIRED' });
  }

  // Rotate token: issue a fresh JWT with a new jti (invalidates old token fingerprint)
  var newToken;
  try {
    var newPayload = {
      sub:               licenseKey,
      plan:              keyRecord.plan || payload.plan || 'pro',
      deviceFingerprint: deviceFingerprint,
      jti:               crypto.randomBytes(16).toString('hex')
    };
    var jwtOpts = { expiresIn: JWT_EXPIRES_IN, algorithm: JWT_ALGORITHM };
    newToken = jwt.sign(newPayload, JWT_SECRET, jwtOpts);
  } catch (e) {
    console.error('[Nebula:revalidate] Token rotation error:', e.message);
    // Non-fatal: return valid without a rotated token
    return json(res, 200, cors, { valid: true });
  }

  return json(res, 200, cors, { valid: true, newToken: newToken });
}

/**
 * ACTION: revoke (user-initiated device deregistration)
 * ───────────────────────────────────────────────────────
 * Body: { action, token, deviceFingerprint }
 *
 * 1. Verify JWT (leniently — allow nearly-expired tokens to revoke cleanly)
 * 2. Remove deviceFingerprint from activated_devices in DB
 * 3. Return { success: true }
 */
async function handleRevoke(body, cors, res) {
  var token             = ((body.token             || '') + '').trim();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();

  if (!token || !isValidFingerprint(deviceFingerprint)) {
    return json(res, 400, cors, { error: 'MISSING_FIELDS' });
  }

  // Decode without expiry enforcement (user might revoke after token expiry)
  var payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, {
      algorithms:      [JWT_ALGORITHM],
      ignoreExpiration: true
    });
  } catch (e) {
    // Invalid signature — refuse
    return json(res, 401, cors, { error: 'TOKEN_INVALID' });
  }

  var licenseKey = payload.sub;

  // Fetch current device list
  var dbResult = await supabaseFetch(
    '/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=id,activated_devices&limit=1'
  );

  if (dbResult.error || !dbResult.data || dbResult.data.length === 0) {
    // Can't reach DB — client already cleared local data, so treat as success
    return json(res, 200, cors, { success: true });
  }

  var keyRecord        = dbResult.data[0];
  var activatedDevices = Array.isArray(keyRecord.activated_devices) ? keyRecord.activated_devices : [];
  var updatedDevices   = activatedDevices.filter(function (d) { return d !== deviceFingerprint; });

  if (updatedDevices.length !== activatedDevices.length) {
    await supabaseFetch(
      '/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id),
      { method: 'PATCH', body: { activated_devices: updatedDevices } }
    );
  }

  return json(res, 200, cors, { success: true });
}

/* ══════════════════════════════════════════════════════════════
   SECTION 4 — MAIN HANDLER (action router)
══════════════════════════════════════════════════════════════ */
module.exports = async function handler(req, res) {

  var cors = corsHeaders(req);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, cors);
    res.end();
    return;
  }

  // Method guard
  if (req.method !== 'POST') {
    return json(res, 405, cors, { error: 'METHOD_NOT_ALLOWED' });
  }

  // Environment variable guard
  if (!JWT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('[Nebula] Missing environment variable(s). ' +
      'JWT_SECRET=' + !!JWT_SECRET +
      ' SUPABASE_URL=' + !!SUPABASE_URL +
      ' SUPABASE_SERVICE_KEY=' + !!SUPABASE_SERVICE_KEY);
    return json(res, 500, cors, { error: 'SERVER_MISCONFIGURATION' });
  }

  // Parse body
  var body;
  try {
    body = await readBody(req);
  } catch (e) {
    var errCode = e.message === 'payload_too_large' ? 'PAYLOAD_TOO_LARGE' : 'INVALID_JSON';
    return json(res, 400, cors, { error: errCode });
  }

  // Route by action field
  var action = ((body.action || '') + '').trim().toLowerCase();

  switch (action) {
    case 'activate':
      return handleActivate(body, cors, res);

    case 'revalidate':
      return handleRevalidate(body, cors, res);

    case 'revoke':
      return handleRevoke(body, cors, res);

    default:
      return json(res, 400, cors, { error: 'UNKNOWN_ACTION', validActions: ['activate', 'revalidate', 'revoke'] });
  }
};
