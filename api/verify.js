'use strict';

const jwt    = require('jsonwebtoken');
const https  = require('https');
const crypto = require('crypto');

const JWT_SECRET           = (process.env.JWT_SECRET           || '').trim();
const SUPABASE_URL         = (process.env.SUPABASE_URL         || '').trim().replace(/\/$/, '');
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

const JWT_ALGORITHM      = 'HS256';
const JWT_EXPIRES_IN     = '30d';
const MAX_PAYLOAD_BYTES  = 8192;
const LICENSE_KEY_REGEX = /^[A-Z0-9]{10,64}$/;

function readBody(req) {
  return new Promise(function (resolve, reject) {
    if (req.body !== undefined && req.body !== null) {
      if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return resolve(req.body);
      if (typeof req.body === 'string' && req.body.trim() !== '') {
        try { return resolve(JSON.parse(req.body)); } catch (e) { return reject(new Error('invalid_json')); }
      }
    }
    var chunks = [];
    var totalBytes = 0;
    req.on('data', function (chunk) {
      totalBytes += chunk.length;
      if (totalBytes > MAX_PAYLOAD_BYTES) return reject(new Error('payload_too_large'));
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', function () {
      var raw = Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/, '').trim();
      if (raw === '') return resolve({});
      try { resolve(JSON.parse(raw)); } catch (e) { reject(new Error('invalid_json')); }
    });
    req.on('error', function (err) { reject(err); });
  });
}

function supabaseFetch(path, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var bodyStr = opts.body ? JSON.stringify(opts.body) : null;
    var url     = new URL(SUPABASE_URL + path);
    var reqOpts = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   opts.method || 'GET',
      headers: {
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': 'Bearer ' + SUPABASE_SERVICE_KEY,
        'Content-Type':  'application/json',
        'Prefer':        'return=representation'
      }
    };
    var req = https.request(reqOpts, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        try {
          var parsed = JSON.parse(Buffer.concat(chunks).toString());
          resolve(res.statusCode >= 400 ? { data: null, error: parsed.message || 'db_error' } : { data: parsed, error: null });
        } catch (e) { resolve({ data: null, error: 'json_parse_error' }); }
      });
    });
    req.on('error', function () { resolve({ data: null, error: 'network_error' }); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

function corsHeaders(req) {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function isValidFingerprint(fp) {
  return (typeof fp === 'string' && fp.length >= 1 && fp.length <= 64 && /^[\x21-\x7E]+$/.test(fp));
}

function json(res, status, headers, body) {
  res.writeHead(status, Object.assign({}, headers, { 'Content-Type': 'application/json' }));
  res.end(JSON.stringify(body));
}

async function handleActivate(body, cors, res) {
  var licenseKey        = ((body.licenseKey        || '') + '').trim().toUpperCase().replace(/-/g, '');
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();

  if (!LICENSE_KEY_REGEX.test(licenseKey)) return json(res, 400, cors, { error: 'INVALID_KEY_FORMAT' });
  if (!isValidFingerprint(deviceFingerprint)) return json(res, 400, cors, { error: 'INVALID_FINGERPRINT' });

  var dbResult = await supabaseFetch('/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=id,key,plan,max_devices,revoked,activated_devices&limit=1');
  if (dbResult.error || !dbResult.data || dbResult.data.length === 0) return json(res, 404, cors, { error: 'KEY_NOT_FOUND' });

  var keyRecord = dbResult.data[0];
  if (keyRecord.revoked) return json(res, 403, cors, { error: 'KEY_REVOKED' });

  var activatedDevices = Array.isArray(keyRecord.activated_devices) ? keyRecord.activated_devices : [];
  if (!activatedDevices.includes(deviceFingerprint)) {
    if (activatedDevices.length >= (keyRecord.max_devices || 2)) return json(res, 403, cors, { error: 'KEY_ALREADY_USED' });
    await supabaseFetch('/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id), { method: 'PATCH', body: { activated_devices: activatedDevices.concat(deviceFingerprint) } });
  }

  var token = jwt.sign({ sub: licenseKey, plan: keyRecord.plan, deviceFingerprint: deviceFingerprint, jti: crypto.randomBytes(16).toString('hex') }, JWT_SECRET, { algorithm: JWT_ALGORITHM });
  return json(res, 200, cors, { token: token, plan: keyRecord.plan });
}

async function handleRevalidate(body, cors, res) {
  var token = ((body.token || '') + '').trim();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();
  if (!token || !isValidFingerprint(deviceFingerprint)) return json(res, 400, cors, { error: 'MISSING_FIELDS' });
  
  var payload;
  try { payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] }); }
  catch (e) { return json(res, 401, cors, { valid: false, error: 'TOKEN_INVALID' }); }

  if (payload.deviceFingerprint && payload.deviceFingerprint !== deviceFingerprint) return json(res, 403, cors, { valid: false, error: 'DEVICE_MISMATCH' });
  return json(res, 200, cors, { valid: true });
}

async function handleRevoke(body, cors, res) {
  var token = ((body.token || '') + '').trim();
  var deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();
  if (!token || !isValidFingerprint(deviceFingerprint)) return json(res, 400, cors, { error: 'MISSING_FIELDS' });

  var payload;
  try { payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM], ignoreExpiration: true }); }
  catch (e) { return json(res, 401, cors, { error: 'TOKEN_INVALID' }); }

  var dbResult = await supabaseFetch('/rest/v1/license_keys?key=eq.' + encodeURIComponent(payload.sub) + '&select=id,activated_devices&limit=1');
  if (dbResult.data && dbResult.data.length > 0) {
    var record = dbResult.data[0];
    var updated = (record.activated_devices || []).filter(function(d) { return d !== deviceFingerprint; });
    await supabaseFetch('/rest/v1/license_keys?id=eq.' + encodeURIComponent(record.id), { method: 'PATCH', body: { activated_devices: updated } });
  }
  return json(res, 200, cors, { success: true });
}

module.exports = async function handler(req, res) {
  var cors = corsHeaders(req);
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }
  if (req.method !== 'POST') return json(res, 405, cors, { error: 'METHOD_NOT_ALLOWED' });

  var body;
  try { body = await readBody(req); } catch (e) { return json(res, 400, cors, { error: 'INVALID_JSON' }); }

  var action = ((body.action || '') + '').trim().toLowerCase();
  if (action === 'activate') return handleActivate(body, cors, res);
  if (action === 'revalidate') return handleRevalidate(body, cors, res);
  if (action === 'revoke') return handleRevoke(body, cors, res);
  return json(res, 400, cors, { error: 'UNKNOWN_ACTION' });
};
