'use strict';

const jwt = require('jsonwebtoken');
const https = require('https');
const crypto = require('crypto');

const JWT_SECRET = (process.env.JWT_SECRET || '').trim();
const SUPABASE_URL = (process.env.SUPABASE_URL || '').trim().replace(/\/$/, '');
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

const JWT_ALGORITHM = 'HS256';
const LICENSE_KEY_REGEX = /^[A-Z0-9]{10,64}$/;

// --- الدوال المساعدة ---
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(raw)); } 
      catch (e) { reject(new Error('INVALID_JSON')); }
    });
  });
}

function json(res, status, cors, body) {
  res.writeHead(status, Object.assign({}, cors, { 'Content-Type': 'application/json' }));
  res.end(JSON.stringify(body));
}

function supabaseFetch(path, opts = {}) {
  return new Promise(resolve => {
    const bodyStr = opts.body ? JSON.stringify(opts.body) : null;
    const url = new URL(SUPABASE_URL + path);
    const req = https.request({
      hostname: url.hostname, path: url.pathname + url.search, method: opts.method || 'GET',
      headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': 'Bearer ' + SUPABASE_SERVICE_KEY, 'Content-Type': 'application/json' }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ data: JSON.parse(data), error: null }); } 
        catch (e) { resolve({ data: null, error: 'db_error' }); }
      });
    });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// --- معالجات الأفعال ---
async function handleActivate(body, cors, res) {
  const licenseKey = ((body.licenseKey || '') + '').trim().toUpperCase().replace(/-/g, '');
  const deviceFingerprint = ((body.deviceFingerprint || '') + '').trim().toLowerCase();
  
  const dbResult = await supabaseFetch('/rest/v1/license_keys?key=eq.' + encodeURIComponent(licenseKey) + '&select=id,plan,max_devices,activated_devices&limit=1');
  if (!dbResult.data || dbResult.data.length === 0) return json(res, 404, cors, { error: 'KEY_NOT_FOUND' });
  
  const keyRecord = dbResult.data[0];
  const activatedDevices = keyRecord.activated_devices || [];
  
  if (!activatedDevices.includes(deviceFingerprint) && activatedDevices.length >= (keyRecord.max_devices || 2)) 
    return json(res, 403, cors, { error: 'KEY_ALREADY_USED' });
  
  if (!activatedDevices.includes(deviceFingerprint)) {
    await supabaseFetch('/rest/v1/license_keys?id=eq.' + encodeURIComponent(keyRecord.id), { 
      method: 'PATCH', body: { activated_devices: activatedDevices.concat(deviceFingerprint) } 
    });
  }
  
  const token = jwt.sign({ sub: licenseKey, deviceFingerprint }, JWT_SECRET, { algorithm: JWT_ALGORITHM });
  return json(res, 200, cors, { token });
}

async function handleRevalidate(body, cors, res) {
  try {
    const payload = jwt.verify(body.token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    if (payload.deviceFingerprint !== body.deviceFingerprint) throw new Error();
    return json(res, 200, cors, { valid: true });
  } catch (e) { return json(res, 401, cors, { valid: false }); }
}

// --- المعالج الرئيسي ---
module.exports = async function handler(req, res) {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }
  
  let body;
  try { body = await readBody(req); } catch (e) { return json(res, 400, cors, { error: 'INVALID_JSON' }); }
  
  console.log("البيانات المستلمة:", JSON.stringify(body));

  if (body.action === 'activate') return await handleActivate(body, cors, res);
  if (body.action === 'revalidate') return await handleRevalidate(body, cors, res);
  
  return json(res, 400, cors, { error: 'UNKNOWN_ACTION' });
};
