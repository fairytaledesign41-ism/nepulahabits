/**
 * ═══════════════════════════════════════════════════════════════
 *  NEBULA — LICENSE KEY HASH GENERATOR
 *  Run with:  node nebula-hash-generator.js
 * ═══════════════════════════════════════════════════════════════
 *
 *  HOW TO USE:
 *  1. Edit the KEYS array below with your new license key(s).
 *  2. Run:  node nebula-hash-generator.js
 *  3. Copy the printed SHA-256 hash(es) into your remote TXT file
 *     (one hash per line, nothing else).
 *  4. Upload / update the TXT file on your server.
 *     The app picks up new keys automatically — no code changes needed.
 *
 *  REMOTE TXT FILE FORMAT (nebula-license-hashes.txt):
 *  ┌──────────────────────────────────────────────────────────────┐
 *  │ a3f1c2d9e4b5...  ← SHA-256 of NEBULA-2024-ALPHA-0001        │
 *  │ 7b0e8f2a1c3d...  ← SHA-256 of NEBULA-2024-ALPHA-0002        │
 *  │ (one 64-char hex hash per line, blank lines are ignored)     │
 *  └──────────────────────────────────────────────────────────────┘
 *
 *  SECURITY NOTES:
 *  • The app hashes user input client-side and compares against this list.
 *  • Raw license keys are NEVER stored or transmitted — only hashes.
 *  • Serve your TXT file over HTTPS with CORS header:
 *      Access-Control-Allow-Origin: *
 *  • For extra security, rotate the HASH_FILE_URL in index.html periodically.
 * ═══════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

/* ── ADD YOUR LICENSE KEYS HERE ──────────────────────────────── */
const KEYS = [
  'NEBULA-2024-ALPHA-0001',
  'NEBULA-2024-ALPHA-0002',
  'NEBULA-X7K9-L2P4-M8R1',
  'NEBULA-B3V5-N9Q2-K6W7',
  'NEBULA-J4M8-D1F3-Z9T5',
  'NEBULA-C2H6-G7Y9-W4P1',
  'NEBULA-R9L5-K3B8-V2X4',
  'NEBULA-M1T4-P7J6-D9N2',
  'NEBULA-F8W2-Z3Q5-H6Y7',
  'NEBULA-K4C9-V1R8-B7M3',
  'NEBULA-P6N3-X2T9-J5L1',
  'NEBULA-D9Z4-M7B2-W8F6',
  'NEBULA-G5Y1-H8K3-Q4R9',
  'NEBULA-V2J7-L6P5-N1X8',
  'NEBULA-Q3T9-D4F2-Z7B6',
  'NEBULA-W8R5-M1K3-C9V4',
  'NEBULA-J6P2-X7L9-T5H1',
  'NEBULA-B4M8-Z1Q6-V3R7',
  'NEBULA-K9D5-F2N8-G4Y3',
  'NEBULA-L1T6-P3J9-X7M2',
  'NEBULA-R5W4-V8K7-D2B1',
  // 'NEBULA-2024-BETA-0001',   ← add more as needed
];
/* ─────────────────────────────────────────────────────────────── */

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

console.log('\n═══════════════════════════════════════════════════════');
console.log('  NEBULA License Key → SHA-256 Hash Generator');
console.log('═══════════════════════════════════════════════════════\n');

const hashes = [];

KEYS.forEach(function (key) {
  const normalized = key.trim().toUpperCase(); // must match app logic
  const hash = sha256(normalized);
  hashes.push(hash);
  console.log(`  KEY   : ${normalized}`);
  console.log(`  HASH  : ${hash}`);
  console.log('  ─────────────────────────────────────────────────────');
});

console.log('\n  ✔  Copy the lines below into your remote TXT file:\n');
console.log('─── nebula-license-hashes.txt ───────────────────────────');
hashes.forEach(h => console.log(h));
console.log('─────────────────────────────────────────────────────────\n');
