/**
 * api/verify.js
 * ─────────────────────────────────────────────────────────────────
 * Vercel Serverless Function — License Key Verification
 * Fixed: 2025-06 — resolved FUNCTION_INVOCATION_FAILED causes:
 *   [1] jsonwebtoken was missing from package.json
 *   [2] require('crypto') was called inline inside the handler
 *   [3] req.body was assumed pre-parsed (not safe in raw Node functions)
 *   [4] env var strings may carry trailing whitespace from the dashboard
 *
 * POST /api/verify
 * Body: { licenseKey: string, deviceFingerprint: string }
 *
 * Returns: { token: string, plan: string }  on success
 *          { error: string }                on failure
 *
 * Required environment variables (Vercel Dashboard → Settings → Env Vars):
 *   JWT_SECRET           — 64-char hex string  (no spaces, no quotes)
 *   SUPABASE_URL         — https://xxxx.supabase.co
 *   SUPABASE_SERVICE_KEY — service_role key (NOT the anon key)
 * ─────────────────────────────────────────────────────────────────
 */

'use strict';

// ─── FIX [1] & [2]: ALL requires hoisted to module top-level ─────────────────
// jsonwebtoken MUST be in package.json > dependencies (see root package.json).
// crypto is a Node built-in; require() must NOT be called inside the handler.
const jwt    = require('jsonwebtoken');
const https  = require('https');
const crypto = require('crypto');           // ← hoisted; was inline before (bug)

/* ══════════════════════════════════════════════════════════════
   SECTION 1 — CONFIG
   FIX [4]: .trim() every env var to strip invisible dashboard whitespace.
══════════════════════════════════════════════════════════════ */
const JWT_SECRET           = (process.env.JWT_SECRET           || '').trim();
const SUPABASE_URL         = (process.env.SUPABASE_URL         || '').trim().replace(/\/$/, '');
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

const JWT_EXPIRES_IN     = '30d';
const LICENSE_KEY_REGEX  = /^NEBULA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
const ALLOWED_ORIGINS    = [
  'https://nepulahabits.vercel.app'   // ← replace with your actual domain
];

/* ══════════════════════════════════════════════════════════════
   SECTION 2 — BODY PARSER
   FIX [3]: Vercel raw Node functions do NOT auto-parse req.body.
   We must manually stream and parse it. Framework functions (e.g.
   Next.js API routes) do this automatically, but plain /api/*.js
   files on Vercel do not when there is no framework configured.
══════════════════════════════════════════════════════════════ */
function readBody(req) {
  return new Promise(function (resolve, reject) {
    // If a framework (Next.js, Express) already parsed it, use that.
    if (req.body && typeof req.body === 'object') {
      return resolve(req.body);
    }
    var raw = '';
    req.setEncoding('utf8');
    req.on('data', function (chunk) {
      raw += chunk;
      // Safety: reject payloads over 8 KB
      if (raw.length > 8192) {
        reject(new Error('payload_too_large'));
      }
    });
    req.on('end', function () {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(new Error('invalid_json'));
      }
    });
    req.on('error', function (e) {
      reject(e);
    });
  });
}

/* ══════════════════════════════════════════════════════════════
   SECTION 3 — SUPABASE REST HELPER
   Calls Supabase's PostgREST HTTP API directly via Node https.
   No SDK required — keeps the cold-start bundle minimal.
══════════════════════════════════════════════════════════════ */
function supabaseFetch(path, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var bodyStr = opts.body ? JSON.stringify(opts.body) : null;
    var method  = opts.method || 'GET';
    var url     = new URL(SUPABASE_URL + path);

    var reqOptions = {
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
      reqOptions.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }

    var req = https.request(reqOptions, function (res) {
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

    req.on('error', function () {
      resolve({ data: null, error: 'network_error' });
    });

    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/* ══════════════════════════════════════════════════════════════
   SECTION 4 — CORS HELPER
══════════════════════════════════════════════════════════════ */
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

/* ══════════════════════════════════════════════════════════════
   SECTION 5 — VALIDATION HELPER
══════════════════════════════════════════════════════════════ */
function isValidFingerprint(fp) {
  return typeof fp === 'string' && /^[a-f0-9]{64}$/.test(fp);
}

/* ══════════════════════════════════════════════════════════════
   SECTION 6 — MAIN HANDLER
══════════════════════════════════════════════════════════════ */
module.exports = async function handler(req, res) {

  // — CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(req));
    res.end();
    return;
  }

  // — Method guard
  if (req.method !== 'POST') {
    res.writeHead(405, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'method_not_allowed' }));
    return;
  }

  // — Env var guard (trimmed above, so empty string = not set)
  if (!JWT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('[Nebula] Missing or blank environment variable(s). ' +
      'JWT_SECRET set: ' + !!JWT_SECRET + ', ' +
      'SUPABASE_URL set: ' + !!SUPABASE_URL + ', ' +
      'SUPABASE_SERVICE_KEY set: ' + !!SUPABASE_SERVICE_KEY);
    res.writeHead(500, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'server_misconfiguration' }));
    return;
  }

  // — Parse body (FIX [3]: manual streaming parser, safe for all Vercel runtimes)
  var body;
  try {
    body = await readBody(req);
  } catch (e) {
    var parseErrMsg = e.message === 'payload_too_large' ? 'payload_too_large' : 'invalid_json';
    res.writeHead(400, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: parseErrMsg }));
    return;
  }

  var licenseKey        = ((body.licenseKey        || '') + '').trim().toUpperCase();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();

  // — Input validation
  if (!LICENSE_KEY_REGEX.test(licenseKey)) {
    res.writeHead(400, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'invalid_key_format' }));
    return;
  }

  if (!isValidFingerprint(deviceFingerprint)) {
    res.writeHead(400, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'invalid_fingerprint' }));
    return;
  }

  // — Look up key in Supabase
  var dbResult = await supabaseFetch(
    '/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=*&limit=1'
  );

  if (dbResult.error) {
    console.error('[Nebula] DB lookup error:', dbResult.error);
    res.writeHead(503, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'db_unavailable' }));
    return;
  }

  var rows = dbResult.data;
  if (!rows || rows.length === 0) {
    res.writeHead(404, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'key_not_found' }));
    return;
  }

  var keyRecord = rows[0];

  // — Revocation check
  if (keyRecord.revoked) {
    res.writeHead(403, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'key_revoked' }));
    return;
  }

  // — Expiry check
  if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
    res.writeHead(403, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'key_expired' }));
    return;
  }

  // — Device management
  var activatedDevices        = Array.isArray(keyRecord.activated_devices)
                                  ? keyRecord.activated_devices
                                  : [];
  var deviceAlreadyRegistered = activatedDevices.includes(deviceFingerprint);

  if (!deviceAlreadyRegistered) {
    if (activatedDevices.length >= keyRecord.max_devices) {
      res.writeHead(403, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
      res.end(JSON.stringify({ error: 'max_devices' }));
      return;
    }

    var updatedDevices = activatedDevices.concat(deviceFingerprint);
    var updateResult   = await supabaseFetch(
      '/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id),
      { method: 'PATCH', body: { activated_devices: updatedDevices } }
    );

    if (updateResult.error) {
      console.error('[Nebula] Device registration error:', updateResult.error);
      // Non-fatal: log and continue — token is still issued
    }
  }

  // — Sign JWT
  // FIX [2]: crypto.randomBytes() now uses the module-level require at the top.
  var payload = {
    sub:    licenseKey,
    plan:   keyRecord.plan || 'pro',
    device: deviceFingerprint,
    jti:    crypto.randomBytes(16).toString('hex')   // ← no inline require()
  };

  var jwtOptions = { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' };

  if (keyRecord.expires_at) {
    var hardExpiry = Math.floor(new Date(keyRecord.expires_at).getTime() / 1000);
    var softExpiry = Math.floor(Date.now() / 1000) + 30 * 86400;
    var ttl        = Math.min(hardExpiry, softExpiry) - Math.floor(Date.now() / 1000);
    jwtOptions.expiresIn = ttl > 0 ? ttl : 1;
  }

  var token;
  try {
    token = jwt.sign(payload, JWT_SECRET, jwtOptions);
  } catch (e) {
    console.error('[Nebula] JWT sign error:', e.message);
    res.writeHead(500, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
    res.end(JSON.stringify({ error: 'token_sign_error' }));
    return;
  }

  // — Success
  res.writeHead(200, Object.assign({}, corsHeaders(req), { 'Content-Type': 'application/json' }));
  res.end(JSON.stringify({ token: token, plan: keyRecord.plan || 'pro' }));
};
