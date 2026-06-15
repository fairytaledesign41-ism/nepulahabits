const jwt = require('jsonwebtoken');
const https = require('https');
const crypto = require('crypto');

// إعدادات الاتصال (تأكد من وجودها في Vercel Settings)
const SUPABASE_URL = (process.env.SUPABASE_URL || '').trim();
const SUPABASE_SERVICE_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

module.exports = async function handler(req, res) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ status: "Error: Missing environment variables" });
  }
  
  res.status(200).json({ status: "System Ready - Env Variables Loaded" });
};
