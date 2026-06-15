const https = require('https');

module.exports = async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL.trim().replace(/\/$/, '');
  const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY.trim();

  const options = {
    hostname: new URL(SUPABASE_URL).hostname,
    path: '/rest/v1/license_keys?select=id&limit=1',
    method: 'GET',
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': 'Bearer ' + SUPABASE_SERVICE_KEY,
      'Content-Type': 'application/json'
    }
  };

  const request = https.request(options, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => {
      res.status(200).json({ status: "Database connected", response: JSON.parse(data) });
    });
  });

  request.on('error', (e) => {
    res.status(500).json({ status: "Database connection failed", error: e.message });
  });

  request.end();
};
