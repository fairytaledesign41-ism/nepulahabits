/**
 * api/verify.js
 * ─────────────────────────────────────────────────────────────────
 * Vercel Serverless Function — License Key Verification
 *
 * POST /api/verify
 * Body: { licenseKey: string, deviceFingerprint: string }
 *
 * Returns: { token: string }  on success
 *          { error: string }  on failure
 *
 * Required environment variables (set in Vercel dashboard):
 *   JWT_SECRET           — 64-char hex secret for signing JWTs
 *   SUPABASE_URL         — e.g. https://xyzabc.supabase.co
 *   SUPABASE_SERVICE_KEY — service_role key (NOT anon key)
 * ─────────────────────────────────────────────────────────────────
 */

const jwt       = require('jsonwebtoken');
const https     = require('https');

/* ══════════════════════════════════════════════════════════════
   SECTION 1 — CONFIG
══════════════════════════════════════════════════════════════ */
const JWT_SECRET          = process.env.JWT_SECRET;
const SUPABASE_URL        = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const JWT_EXPIRES_IN      = '30d';   // token validity
const LICENSE_KEY_REGEX   = /^NEBULA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
const ALLOWED_ORIGINS     = ['https://your-nebula-domain.vercel.app']; // update to your domain

/* ══════════════════════════════════════════════════════════════
   SECTION 2 — SUPABASE REST HELPER
   Uses the Supabase PostgREST HTTP API without the npm package
   so this function has zero cold-start overhead from heavy SDKs.
   Install: npm install jsonwebtoken   (only dependency)
══════════════════════════════════════════════════════════════ */

/**
 * Minimal Supabase PostgREST fetch helper.
 * @param {string} path    e.g. '/rest/v1/license_keys?key=eq.XXXX&select=*'
 * @param {Object} [opts]  { method, body }
 * @returns {Promise<{ data: any, error: string|null }>}
 */
function supabaseFetch(path, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var url    = new URL(SUPABASE_URL + path);
    var body   = opts.body ? JSON.stringify(opts.body) : null;
    var method = opts.method || 'GET';

    var options = {
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
    if (body) options.headers['Content-Length'] = Buffer.byteLength(body);

    var req = https.request(options, function (res) {
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

    req.on('error', function (e) {
      resolve({ data: null, error: 'network_error' });
    });

    if (body) req.write(body);
    req.end();
  });
}

/* ══════════════════════════════════════════════════════════════
   SECTION 3 — CORS HELPER
══════════════════════════════════════════════════════════════ */
function corsHeaders(req) {
  var origin = req.headers.origin || '';
  var allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary':                         'Origin'
  };
}

/* ══════════════════════════════════════════════════════════════
   SECTION 4 — VALIDATION HELPERS
══════════════════════════════════════════════════════════════ */
function isValidFingerprint(fp) {
  return typeof fp === 'string' && /^[a-f0-9]{64}$/.test(fp);
}

/* ══════════════════════════════════════════════════════════════
   SECTION 5 — MAIN HANDLER
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
    res.writeHead(405, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'method_not_allowed' }));
    return;
  }

  // — Env var guard
  if (!JWT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('[Nebula] Missing environment variables');
    res.writeHead(500, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'server_misconfiguration' }));
    return;
  }

  // — Parse body (Vercel parses JSON automatically when Content-Type is application/json)
  var body = req.body || {};
  var licenseKey        = (body.licenseKey        || '').trim().toUpperCase();
  var deviceFingerprint = (body.deviceFingerprint || '').trim().toLowerCase();

  // — Input validation
  if (!LICENSE_KEY_REGEX.test(licenseKey)) {
    res.writeHead(400, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_key_format' }));
    return;
  }

  if (!isValidFingerprint(deviceFingerprint)) {
    res.writeHead(400, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_fingerprint' }));
    return;
  }

  // — Look up key in Supabase
  var dbResult = await supabaseFetch(
    '/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=*&limit=1'
  );

  if (dbResult.error) {
    console.error('[Nebula] DB lookup error:', dbResult.error);
    res.writeHead(503, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'db_unavailable' }));
    return;
  }

  var rows = dbResult.data;
  if (!rows || rows.length === 0) {
    res.writeHead(404, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'key_not_found' }));
    return;
  }

  var keyRecord = rows[0];

  // — Revocation check
  if (keyRecord.revoked) {
    res.writeHead(403, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'key_revoked' }));
    return;
  }

  // — Expiry check
  if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
    res.writeHead(403, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'key_expired' }));
    return;
  }

  // — Device management
  var activatedDevices = keyRecord.activated_devices || [];

  // Already registered on this device → just refresh token
  var deviceAlreadyRegistered = activatedDevices.includes(deviceFingerprint);

  if (!deviceAlreadyRegistered) {
    // New device — check limit
    if (activatedDevices.length >= keyRecord.max_devices) {
      res.writeHead(403, { ...corsHeaders(req), 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'max_devices' }));
      return;
    }

    // Register device
    var updatedDevices = activatedDevices.concat(deviceFingerprint);
    var updateResult = await supabaseFetch(
      '/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id),
      {
        method: 'PATCH',
        body: { activated_devices: updatedDevices }
      }
    );

    if (updateResult.error) {
      console.error('[Nebula] Device registration error:', updateResult.error);
      // Non-fatal: proceed but log
    }
  }

  // — Sign JWT
  var payload = {
    sub:    licenseKey,
    plan:   keyRecord.plan || 'pro',
    device: deviceFingerprint,
    jti:    require('crypto').randomBytes(16).toString('hex')
  };

  // If the key has a hard expiry, honour it in the JWT too
  var jwtOptions = { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' };
  if (keyRecord.expires_at) {
    var hardExpiry = Math.floor(new Date(keyRecord.expires_at).getTime() / 1000);
    var softExpiry = Math.floor(Date.now() / 1000) + 30 * 86400;
    jwtOptions.expiresIn = Math.min(hardExpiry, softExpiry) - Math.floor(Date.now() / 1000);
    if (jwtOptions.expiresIn <= 0) jwtOptions.expiresIn = 1;
  }

  var token;
  try {
    token = jwt.sign(payload, JWT_SECRET, jwtOptions);
  } catch (e) {
    console.error('[Nebula] JWT sign error:', e);
    res.writeHead(500, { ...corsHeaders(req), 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'token_sign_error' }));
    return;
  }

  // — Success
  res.writeHead(200, { ...corsHeaders(req), 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    token: token,
    plan:  keyRecord.plan || 'pro'
  }));
};
