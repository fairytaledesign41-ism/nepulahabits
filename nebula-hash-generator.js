/**
 * ═══════════════════════════════════════════════════════════════
 *  NEBULA — LICENSE KEY HASH GENERATOR
 *  Run with:  node nebula-hash-generator.js
 * ═══════════════════════════════════════════════════════════════
 *
 *  HOW TO USE:
 *  1. Add your plain-text license keys to the KEYS array below.
 *  2. Run: node nebula-hash-generator.js
 *  3. Copy the output hashes into nebula-license-hashes.txt
 *     (one hash per line, nothing else).
 *  4. Upload the TXT file to your GitHub repo.
 *     The app verifies against this file automatically.
 *
 *  SECURITY NOTES:
 *  • Raw keys are NEVER stored or transmitted — only their SHA-256 hashes.
 *  • The TXT file on GitHub is safe to make public; hashes cannot be
 *    reversed back into the original keys.
 *  • To revoke a key, simply delete its hash from the TXT file.
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
];
/* ─────────────────────────────────────────────────────────────── */

/**
 * Returns the SHA-256 hex digest of a string.
 * Input is normalized (trimmed + uppercased) to match the app's logic.
 */
function sha256(str) {
  const normalized = str.trim().toUpperCase();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

/* ── Run ─────────────────────────────────────────────────────── */
console.log('\n════════════════════════════════════════════════════════');
console.log('  NEBULA  ·  License Key → SHA-256 Hash Generator');
console.log('════════════════════════════════════════════════════════\n');

const hashes = KEYS.map(key => {
  const hash = sha256(key);
  console.log(`  KEY  : ${key.trim().toUpperCase()}`);
  console.log(`  HASH : ${hash}`);
  console.log('  ──────────────────────────────────────────────────────');
  return hash;
});

console.log('\n  ✔  Paste the block below into nebula-license-hashes.txt\n');
console.log('──── nebula-license-hashes.txt (copy from here) ─────────');
hashes.forEach(h => console.log(h));
console.log('──────────────────────────────────────────────────────────\n');
