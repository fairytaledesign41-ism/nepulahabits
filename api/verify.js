'use strict';

const jwt    = require('jsonwebtoken');
const https  = require('https');
const crypto = require('crypto');

// 1. CONFIGURATION
const JWT_SECRET           = (process.env.JWT_SECRET            || '').trim();
const SUPABASE_URL         = (process.env.SUPABASE_URL          || '').trim().replace(/\/$/, '');
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

const JWT_ALGORITHM        = 'HS256';
const JWT_EXPIRES_IN       = '30d';
const MAX_PAYLOAD_BYTES    = 8192;
const LICENSE_KEY_REGEX    = /^[A-Z0-9]{10,64}$/;
const ALLOWED_ORIGINS      = ['https://nepulahabits.vercel.app'];

// 2. UTILITIES
function readBody(req) {
  return new Promise(function (resolve, reject) {
    if (req.body && typeof req.body === 'object') return resolve(req.body);
    var raw = '';
    req.setEncoding('utf8');
    req.on('data', function (chunk) {
      raw += chunk;
      if (raw.length > MAX_PAYLOAD_BYTES) reject(new Error('payload_too_large'));
    });
    req.on('end', function () {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(new Error('invalid_json')); }
    });
    req.on('error', reject);
  });
}

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
    if (bodyStr) reqOpts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    var req = https.request(reqOpts, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        try {
          var parsed = JSON.parse(Buffer.concat(chunks).toString());
          if (res.statusCode >= 400) resolve({ data: null, error: parsed.message || parsed.error || 'db_error' });
          else resolve({ data: parsed, error: null });
        } catch (e) { resolve({ data: null, error: 'json_parse_error' }); }
      });
    });
    req.on('error', function () { resolve({ data: null, error: 'network_error' }); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

function corsHeaders(req) {
  var origin  = (req.headers && req.headers.origin) || '';
  var allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return { 'Access-Control-Allow-Origin': allowed, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
}

function isValidFingerprint(fp) { return typeof fp === 'string' && /^[a-f0-9]{1,64}$/.test(fp) && fp.length >= 1; }
function json(res, status, headers, body) { res.writeHead(status, Object.assign({}, headers, { 'Content-Type': 'application/json' })); res.end(JSON.stringify(body)); }

// 3. ACTION HANDLERS
async function handleActivate(body, cors, res) {
  var licenseKey = ((body.licenseKey || '') + '').trim().toUpperCase().replace(/-/g, '');
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();
  if (!LICENSE_KEY_REGEX.test(licenseKey) || !isValidFingerprint(deviceFingerprint)) return json(res, 400, cors, { error: 'INVALID_INPUT' });
  var dbResult = await supabaseFetch('/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=id,key,plan,max_devices,revoked,activated_devices&limit=1');
  if (dbResult.error || !dbResult.data || dbResult.data.length === 0) return json(res, 404, cors, { error: 'KEY_NOT_FOUND' });
  var keyRecord = dbResult.data[0];
  if (keyRecord.revoked) return json(res, 403, cors, { error: 'KEY_REVOKED' });
  var activatedDevices = Array.isArray(keyRecord.activated_devices) ? keyRecord.activated_devices : [];
  if (!activatedDevices.includes(deviceFingerprint) && activatedDevices.length >= (keyRecord.max_devices || 2)) return json(res, 403, cors, { error: 'KEY_ALREADY_USED' });
  if (!activatedDevices.includes(deviceFingerprint)) await supabaseFetch('/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id), { method: 'PATCH', body: { activated_devices: activatedDevices.concat(deviceFingerprint) } });
  var token = jwt.sign({ sub: licenseKey, plan: keyRecord.plan || 'pro', deviceFingerprint: deviceFingerprint, jti: crypto.randomBytes(16).toString('hex') }, JWT_SECRET, { algorithm: JWT_ALGORITHM });
  return json(res, 200, cors, { token, plan: keyRecord.plan || 'pro' });
}

async function handleRevalidate(body, cors, res) {
  var token = ((body.token || '') + '').trim();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();
  try { var payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] }); if (payload.deviceFingerprint !== deviceFingerprint) throw new Error(); } catch (e) { return json(res, 401, cors, { valid: false }); }
  return json(res, 200, cors, { valid: true });
}

async function handleRevoke(body, cors, res) {
  var token = ((body.token || '') + '').trim();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();
  try { var payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM], ignoreExpiration: true }); } catch (e) { return json(res, 401, cors, { error: 'TOKEN_INVALID' }); }
  var dbResult = await supabaseFetch('/rest/v1/license_keys?key=eq.' + encodeURIComponent(payload.sub) + '&select=id,activated_devices&limit=1');
  if (dbResult.data && dbResult.data.length > 0) {
    var keyRecord = dbResult.data[0];
    var updated = (Array.isArray(keyRecord.activated_devices) ? keyRecord.activated_devices : []).filter(d => d !== deviceFingerprint);
    await supabaseFetch('/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id), { method: 'PATCH', body: { activated_devices: updated } });
  }
  return json(res, 200, cors, { success: true });
}

// 4. MAIN HANDLER
module.exports = async function handler(req, res) {
  var cors = corsHeaders(req);
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }
  if (req.method !== 'POST') return json(res, 405, cors, { error: 'METHOD_NOT_ALLOWED' });
  if (!JWT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) return json(res, 500, cors, { error: 'SERVER_MISCONFIGURATION' });
  var body; try { body = await readBody(req); } catch (e) { return json(res, 400, cors, { error: 'INVALID_JSON' }); }
  var action = ((body.action || '') + '').trim().toLowerCase();
  switch (action) {
    case 'activate':   return handleActivate(body, cors, res);
    case 'revalidate': return handleRevalidate(body, cors, res);
    case 'revoke':     return handleRevoke(body, cors, res);
    default:           return json(res, 400, cors, { error: 'UNKNOWN_ACTION' });
  }
};
