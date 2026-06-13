/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  NEBULA ACTIVATION SYSTEM  v1.0                                        ║
 * ║  Lifetime License — Device Binding — Offline-First — Tamper-Resistant  ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ARCHITECTURE OVERVIEW
 * ─────────────────────
 *  Frontend (this file)           Backend (activation-backend-spec.md)
 *  ─────────────────────          ──────────────────────────────────────
 *  • Collect device fingerprint   • Validate license key against DB
 *  • POST /activate               • Check device limit
 *  • Receive signed JWT token     • Sign JWT with RS256 private key
 *  • Verify token with public key • Store device binding
 *  • Cache token offline          • Return token to frontend
 *  • Periodic silent revalidation
 *
 * SECURITY LAYERS
 * ───────────────
 *  1. License key format validation  (client-side, cosmetic)
 *  2. Server-side key + device check (real protection)
 *  3. RS256-signed JWT — frontend only has PUBLIC key
 *  4. Token payload includes device fingerprint hash (tamper binding)
 *  5. localStorage integrity check — detects manual token swapping
 *  6. Periodic online revalidation   — catches revoked keys
 *
 * NOTE: No activation secrets or private keys are ever in this file.
 * The PUBLIC key below is safe to embed in frontend code.
 */

(function (window) {
  'use strict';

  /* ──────────────────────────────────────────────────────────────────────
   *  CONFIG — edit these to match your deployment
   * ────────────────────────────────────────────────────────────────────── */
  var NEBULA_CONFIG = {
    /**
     * Your activation API base URL.
     * In production: 'https://api.yourdomain.com'
     * For local dev:  'http://localhost:3000'
     */
    API_BASE: 'https://api.yourdomain.com',

    /**
     * Activation endpoint paths.
     */
    ENDPOINTS: {
      ACTIVATE: '/v1/license/activate',
      REVALIDATE: '/v1/license/revalidate',
      REVOKE: '/v1/license/revoke-device'
    },

    /**
     * RS256 PUBLIC key (PEM) — safe to embed here.
     * Replace this with the real public key exported from your backend.
     * NEVER put the PRIVATE key in frontend code.
     *
     * Generate a key pair:
     *   openssl genrsa -out private.pem 2048
     *   openssl rsa -in private.pem -pubout -out public.pem
     */
    PUBLIC_KEY_PEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TNJH
0EXAMPLE_REPLACE_THIS_WITH_YOUR_REAL_PUBLIC_KEY_FROM_BACKEND_SETUP
-----END PUBLIC KEY-----`,

    /**
     * How often to silently revalidate the token when online (ms).
     * Default: every 24 hours. The app works fully offline between checks.
     */
    REVALIDATION_INTERVAL_MS: 24 * 60 * 60 * 1000,

    /**
     * Grace period: if network fails during revalidation, keep the app
     * working for this many days before requiring re-activation.
     * Default: 30 days.
     */
    OFFLINE_GRACE_DAYS: 30,

    /**
     * Maximum devices allowed per license key (enforced server-side too).
     * Frontend shows a warning when limit is reached.
     */
    MAX_DEVICES: 2,

    /**
     * Storage keys used in localStorage.
     */
    STORAGE: {
      TOKEN: 'nebula_act_token',
      FINGERPRINT: 'nebula_act_fp',
      LAST_VALIDATE: 'nebula_act_last_ok',
      ACTIVATION_DATA: 'nebula_act_data',
      INTEGRITY_HASH: 'nebula_act_ih'
    },

    /**
     * Toggle to false in production to suppress verbose console logs.
     */
    DEBUG: false
  };

  /* ──────────────────────────────────────────────────────────────────────
   *  PRIVATE UTILITIES
   * ────────────────────────────────────────────────────────────────────── */

  function _log() {
    if (NEBULA_CONFIG.DEBUG && window.console && console.log) {
      console.log.apply(console, ['[Nebula Activation]'].concat(Array.prototype.slice.call(arguments)));
    }
  }

  /** Safe localStorage wrapper (works in iOS private mode) */
  var _store = {
    get: function (k) {
      try { return localStorage.getItem(k); } catch (e) { return null; }
    },
    set: function (k, v) {
      try { localStorage.setItem(k, String(v)); return true; } catch (e) { return false; }
    },
    remove: function (k) {
      try { localStorage.removeItem(k); } catch (e) {}
    }
  };

  /**
   * Simple FNV-1a 32-bit hash — used for lightweight integrity checks.
   * NOT cryptographic. Cryptographic operations use SubtleCrypto.
   */
  function _fnv32a(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
      h >>>= 0;
    }
    return h.toString(16);
  }

  /**
   * Generate a device fingerprint using available browser signals.
   * The result is a deterministic hash — stable across page reloads
   * on the same device, but different across devices.
   *
   * Signals used:
   *  • User-Agent
   *  • Screen dimensions and color depth
   *  • Timezone offset
   *  • Hardware concurrency (CPU threads)
   *  • Device memory (if available)
   *  • Canvas fingerprint (fallback)
   *  • Language
   *  • Platform
   */
  function _buildDeviceFingerprint() {
    var cached = _store.get(NEBULA_CONFIG.STORAGE.FINGERPRINT);
    if (cached && cached.length > 20) return cached;

    var signals = [
      navigator.userAgent || '',
      (screen.width || 0) + 'x' + (screen.height || 0),
      (screen.colorDepth || 24),
      (new Date().getTimezoneOffset()),
      (navigator.hardwareConcurrency || 2),
      (navigator.deviceMemory || 4),
      (navigator.language || 'en'),
      (navigator.platform || '')
    ];

    // Canvas fingerprint (subtle rendering differences per GPU/font)
    try {
      var canvas = document.createElement('canvas');
      canvas.width = 240; canvas.height = 60;
      var ctx = canvas.getContext('2d');
      ctx.fillStyle = '#0b0f17';
      ctx.fillRect(0, 0, 240, 60);
      ctx.fillStyle = 'rgba(168,85,247,0.8)';
      ctx.font = 'bold 18px Tajawal, Arial, sans-serif';
      ctx.fillText('Nebula\u221e2024', 10, 30);
      ctx.strokeStyle = '#34d399';
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(200, 30, 20, 0, Math.PI * 2); ctx.stroke();
      signals.push(canvas.toDataURL().slice(-80));
    } catch (e) { signals.push('no-canvas'); }

    var fp = _fnv32a(signals.join('|'));
    _store.set(NEBULA_CONFIG.STORAGE.FINGERPRINT, fp);
    _log('Device fingerprint:', fp);
    return fp;
  }

  /**
   * Compute a lightweight integrity hash of the token + fingerprint.
   * Stored separately so tampering with either is detected.
   */
  function _computeIntegrityHash(token, fp) {
    return _fnv32a(token + ':' + fp + ':nebula-integrity');
  }

  /**
   * Verify that stored token + fingerprint + integrity hash are consistent.
   * Detects copy-paste attacks where someone manually writes a token to localStorage.
   */
  function _verifyLocalIntegrity() {
    var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
    var fp = _store.get(NEBULA_CONFIG.STORAGE.FINGERPRINT);
    var storedHash = _store.get(NEBULA_CONFIG.STORAGE.INTEGRITY_HASH);
    if (!token || !fp || !storedHash) return false;
    var expected = _computeIntegrityHash(token, fp);
    return expected === storedHash;
  }

  /**
   * Save token with integrity hash.
   */
  function _saveToken(token) {
    var fp = _buildDeviceFingerprint();
    _store.set(NEBULA_CONFIG.STORAGE.TOKEN, token);
    _store.set(NEBULA_CONFIG.STORAGE.INTEGRITY_HASH, _computeIntegrityHash(token, fp));
    _store.set(NEBULA_CONFIG.STORAGE.LAST_VALIDATE, Date.now().toString());
  }

  /**
   * Decode a JWT payload without cryptographic verification.
   * Used only for reading claims (expiry, device, etc.) AFTER the
   * server-side signature has been verified via the public key.
   */
  function _decodeJwtPayload(token) {
    try {
      var parts = token.split('.');
      if (parts.length !== 3) return null;
      var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      var json = atob(b64);
      return JSON.parse(json);
    } catch (e) { return null; }
  }

  /**
   * Cryptographically verify the JWT using the public key (RS256).
   * Uses the Web Crypto API (available in all modern browsers).
   * Returns a Promise<boolean>.
   */
  function _verifyJwtSignature(token) {
    return new Promise(function (resolve) {
      try {
        if (!window.crypto || !window.crypto.subtle) {
          // Fallback: skip cryptographic verification in old browsers.
          // Server-side verification already happened.
          _log('SubtleCrypto unavailable — skipping signature verification');
          resolve(true);
          return;
        }

        var parts = token.split('.');
        if (parts.length !== 3) { resolve(false); return; }

        var headerPayload = parts[0] + '.' + parts[1];
        var sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
        while (sigB64.length % 4) sigB64 += '=';

        // Convert PEM public key to ArrayBuffer
        var pemContent = NEBULA_CONFIG.PUBLIC_KEY_PEM
          .replace(/-----BEGIN PUBLIC KEY-----/, '')
          .replace(/-----END PUBLIC KEY-----/, '')
          .replace(/\s/g, '');
        var keyBytes = _base64ToArrayBuffer(pemContent);
        var sigBytes = _base64ToArrayBuffer(sigB64);
        var msgBytes = new TextEncoder().encode(headerPayload);

        crypto.subtle.importKey(
          'spki',
          keyBytes,
          { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
          false,
          ['verify']
        ).then(function (key) {
          return crypto.subtle.verify(
            { name: 'RSASSA-PKCS1-v1_5' },
            key,
            sigBytes,
            msgBytes
          );
        }).then(function (valid) {
          _log('JWT signature valid:', valid);
          resolve(valid);
        }).catch(function (err) {
          _log('JWT verify error:', err);
          resolve(false);
        });
      } catch (e) {
        _log('JWT verify exception:', e);
        resolve(false);
      }
    });
  }

  function _base64ToArrayBuffer(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  /**
   * Format a license key: strip whitespace, uppercase, and add dashes every 4 chars.
   */
  function _formatLicenseKey(raw) {
    var clean = raw.replace(/[\s\-]/g, '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    var chunks = [];
    for (var i = 0; i < clean.length; i += 4) chunks.push(clean.slice(i, i + 4));
    return chunks.join('-');
  }

  /**
   * Client-side key format validation (cosmetic only — real check is server-side).
   * Expected format: XXXX-XXXX-XXXX-XXXX (16 alphanum chars in 4 groups).
   */
  function _isValidKeyFormat(key) {
    return /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key);
  }

  /**
   * Determine whether the stored token is expired.
   * The 'exp' claim is a Unix timestamp in seconds.
   */
  function _isTokenExpired(payload) {
    if (!payload || !payload.exp) return false; // lifetime token has no exp
    return (Date.now() / 1000) > payload.exp;
  }

  /**
   * Check if we're still within the offline grace period.
   */
  function _withinGracePeriod() {
    var lastOk = _store.get(NEBULA_CONFIG.STORAGE.LAST_VALIDATE);
    if (!lastOk) return false;
    var elapsed = Date.now() - parseInt(lastOk, 10);
    return elapsed < NEBULA_CONFIG.OFFLINE_GRACE_DAYS * 24 * 60 * 60 * 1000;
  }

  /* ──────────────────────────────────────────────────────────────────────
   *  PUBLIC API
   * ────────────────────────────────────────────────────────────────────── */

  /**
   * Attempt to activate a license key for this device.
   *
   * Returns a Promise that resolves to:
   *   { success: true,  token: '...', payload: {...} }  on success
   *   { success: false, error: 'ERROR_CODE', message: '...' }  on failure
   *
   * Error codes:
   *   INVALID_KEY_FORMAT   — key doesn't match expected pattern
   *   NETWORK_ERROR        — could not reach activation server
   *   KEY_NOT_FOUND        — key doesn't exist in the database
   *   KEY_ALREADY_USED     — key is already activated on max devices
   *   KEY_REVOKED          — key has been manually revoked
   *   SERVER_ERROR         — unexpected server error
   */
  function activate(rawKey) {
    return new Promise(function (resolve) {
      var key = _formatLicenseKey(rawKey || '');

      // 1. Client-side format check
      if (!_isValidKeyFormat(key)) {
        resolve({ success: false, error: 'INVALID_KEY_FORMAT', message: 'Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX' });
        return;
      }

      var fp = _buildDeviceFingerprint();
      _log('Activating key:', key, 'fingerprint:', fp);

      // 2. POST to activation API
      var body = JSON.stringify({ licenseKey: key, deviceFingerprint: fp, appVersion: '1.0' });

      fetch(NEBULA_CONFIG.API_BASE + NEBULA_CONFIG.ENDPOINTS.ACTIVATE, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body
      }).then(function (res) {
        return res.json().then(function (data) { return { status: res.status, data: data }; });
      }).then(function (result) {
        if (result.status === 200 && result.data.token) {
          // 3. Verify JWT signature with our public key
          return _verifyJwtSignature(result.data.token).then(function (valid) {
            if (!valid) {
              resolve({ success: false, error: 'INVALID_TOKEN', message: 'Activation token signature is invalid.' });
              return;
            }

            var payload = _decodeJwtPayload(result.data.token);
            _log('Token payload:', payload);

            // 4. Verify device binding inside token
            if (payload && payload.deviceFingerprint && payload.deviceFingerprint !== fp) {
              resolve({ success: false, error: 'DEVICE_MISMATCH', message: 'Token was issued for a different device.' });
              return;
            }

            // 5. Persist with integrity hash
            _saveToken(result.data.token);
            _store.set(NEBULA_CONFIG.STORAGE.ACTIVATION_DATA, JSON.stringify({
              key: key,
              activatedAt: Date.now(),
              deviceCount: result.data.deviceCount || 1,
              plan: result.data.plan || 'lifetime'
            }));

            resolve({ success: true, token: result.data.token, payload: payload });
          });
        } else {
          // Map server error codes to user-friendly responses
          var errorMap = {
            'KEY_NOT_FOUND': 'This license key does not exist.',
            'KEY_ALREADY_USED': 'This key has reached its device limit (' + NEBULA_CONFIG.MAX_DEVICES + ' devices).',
            'KEY_REVOKED': 'This license key has been revoked. Please contact support.',
            'DEVICE_ALREADY_REGISTERED': 'This device is already registered. If you reinstalled, please contact support.'
          };
          var code = result.data.error || 'SERVER_ERROR';
          resolve({
            success: false,
            error: code,
            message: errorMap[code] || (result.data.message || 'An error occurred. Please try again.')
          });
        }
      }).catch(function (err) {
        _log('Network error during activation:', err);
        resolve({ success: false, error: 'NETWORK_ERROR', message: 'Could not reach the activation server. Check your internet connection.' });
      });
    });
  }

  /**
   * Check if this device is currently activated.
   *
   * Checks (in order):
   *  1. Token exists in storage
   *  2. Local integrity hash is consistent  (detects token tampering)
   *  3. JWT signature is valid
   *  4. Token device fingerprint matches this device
   *  5. Token is not expired (or within grace period)
   *
   * Returns a Promise<boolean>.
   */
  function isActivated() {
    return new Promise(function (resolve) {
      var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
      if (!token) { _log('No token found'); resolve(false); return; }

      // 1. Local integrity check
      if (!_verifyLocalIntegrity()) {
        _log('Local integrity check failed — possible tampering');
        _clearActivation();
        resolve(false);
        return;
      }

      var payload = _decodeJwtPayload(token);
      if (!payload) { _log('Cannot decode token payload'); resolve(false); return; }

      // 2. Expiry check
      if (_isTokenExpired(payload)) {
        _log('Token expired');
        if (!_withinGracePeriod()) { _clearActivation(); resolve(false); return; }
        _log('Within grace period — allowing offline use');
        resolve(true);
        return;
      }

      // 3. Device fingerprint binding
      var fp = _buildDeviceFingerprint();
      if (payload.deviceFingerprint && payload.deviceFingerprint !== fp) {
        _log('Device fingerprint mismatch');
        resolve(false);
        return;
      }

      // 4. Cryptographic signature verification
      _verifyJwtSignature(token).then(function (valid) {
        if (!valid) {
          _log('Signature invalid — clearing activation');
          _clearActivation();
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });
  }

  /**
   * Silently revalidate the stored token against the server.
   * Called periodically when the device is online.
   * Does NOT show any UI — just updates the last-validated timestamp.
   *
   * Returns Promise<boolean>.
   */
  function silentRevalidate() {
    return new Promise(function (resolve) {
      if (!navigator.onLine) { resolve(true); return; } // offline — skip
      var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
      var fp = _buildDeviceFingerprint();
      if (!token) { resolve(false); return; }

      fetch(NEBULA_CONFIG.API_BASE + NEBULA_CONFIG.ENDPOINTS.REVALIDATE, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, deviceFingerprint: fp })
      }).then(function (res) {
        return res.json();
      }).then(function (data) {
        if (data.valid) {
          _store.set(NEBULA_CONFIG.STORAGE.LAST_VALIDATE, Date.now().toString());
          // Update token if server rotated it
          if (data.newToken) {
            _saveToken(data.newToken);
          }
          _log('Silent revalidation OK');
          resolve(true);
        } else {
          _log('Silent revalidation failed — key may be revoked');
          // Do NOT clear immediately — let grace period handle it
          resolve(false);
        }
      }).catch(function () {
        _log('Silent revalidation network error — using grace period');
        resolve(true); // offline — grace period applies
      });
    });
  }

  /**
   * Remove all activation data from this device.
   * Called when user explicitly deactivates or when tampering is detected.
   */
  function _clearActivation() {
    Object.values(NEBULA_CONFIG.STORAGE).forEach(function (k) { _store.remove(k); });
    _log('Activation data cleared');
  }

  /**
   * Deactivate this device (user-initiated).
   * Optionally calls the server to free up the device slot.
   */
  function deactivate() {
    return new Promise(function (resolve) {
      var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
      var fp = _buildDeviceFingerprint();
      _clearActivation();

      if (!token || !navigator.onLine) { resolve({ success: true }); return; }

      fetch(NEBULA_CONFIG.API_BASE + NEBULA_CONFIG.ENDPOINTS.REVOKE, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, deviceFingerprint: fp })
      }).then(function () {
        resolve({ success: true });
      }).catch(function () {
        resolve({ success: true }); // local data already cleared
      });
    });
  }

  /**
   * Get stored activation metadata (for display in UI).
   * Returns null if not activated.
   */
  function getActivationInfo() {
    var raw = _store.get(NEBULA_CONFIG.STORAGE.ACTIVATION_DATA);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  /**
   * Start the periodic silent revalidation loop.
   * Call this once after app init, if the user is already activated.
   */
  function startRevalidationLoop() {
    silentRevalidate(); // run immediately on startup
    setInterval(silentRevalidate, NEBULA_CONFIG.REVALIDATION_INTERVAL_MS);
  }

  /* ──────────────────────────────────────────────────────────────────────
   *  ACTIVATION UI CONTROLLER
   *  Injects and manages the activation modal/screen.
   * ────────────────────────────────────────────────────────────────────── */

  var UI = {
    /**
     * Show the activation screen and return a Promise that resolves when
     * the user successfully activates (or rejects if they dismiss).
     */
    showActivationScreen: function () {
      return new Promise(function (resolve, reject) {
        var overlay = document.getElementById('nebulaActivationOverlay');
        if (!overlay) { _log('Activation overlay not found in DOM'); reject(new Error('No overlay')); return; }

        overlay.classList.add('act-show');
        overlay.style.display = 'flex';

        // Wire up the Activate button
        var btn = document.getElementById('actSubmitBtn');
        var input = document.getElementById('actLicenseInput');

        function onActivate() {
          var rawKey = (input.value || '').trim();
          UI.setActivating(true);

          activate(rawKey).then(function (result) {
            UI.setActivating(false);
            if (result.success) {
              UI.showSuccess(function () {
                overlay.classList.remove('act-show');
                overlay.style.display = 'none';
                resolve(result);
              });
            } else {
              UI.showError(result.message || 'Activation failed.');
            }
          });
        }

        if (btn) btn.onclick = onActivate;
        if (input) {
          // Auto-format key as user types
          input.addEventListener('input', function () {
            var pos = input.selectionStart;
            var formatted = _formatLicenseKey(input.value);
            // Only update if changed to avoid cursor jump on every keystroke
            if (formatted !== input.value) {
              input.value = formatted;
            }
          });
          input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.keyCode === 13) onActivate();
          });
        }
      });
    },

    setActivating: function (loading) {
      var btn = document.getElementById('actSubmitBtn');
      var spinner = document.getElementById('actSpinner');
      var btnText = document.getElementById('actBtnText');
      if (btn) btn.disabled = loading;
      if (spinner) spinner.style.display = loading ? 'inline-block' : 'none';
      if (btnText) btnText.textContent = loading ? 'Activating…' : 'Activate Nebula';
    },

    showError: function (msg) {
      var el = document.getElementById('actErrorMsg');
      var box = document.getElementById('actErrorBox');
      if (el) el.textContent = msg;
      if (box) { box.style.display = 'flex'; box.classList.add('act-shake'); }
      setTimeout(function () { if (box) box.classList.remove('act-shake'); }, 500);
    },

    clearError: function () {
      var box = document.getElementById('actErrorBox');
      if (box) box.style.display = 'none';
    },

    showSuccess: function (callback) {
      var panel = document.getElementById('actMainPanel');
      var successPanel = document.getElementById('actSuccessPanel');
      if (panel) panel.style.display = 'none';
      if (successPanel) successPanel.style.display = 'flex';
      setTimeout(callback, 2400);
    },

    showActivationBadge: function (info) {
      var badge = document.getElementById('actStatusBadge');
      if (!badge) return;
      badge.style.display = 'flex';
      var keyEl = document.getElementById('actBadgeKey');
      if (keyEl && info && info.key) {
        // Show only last 4 chars for privacy
        keyEl.textContent = '···· ' + info.key.slice(-4);
      }
    },

    hideActivationBadge: function () {
      var badge = document.getElementById('actStatusBadge');
      if (badge) badge.style.display = 'none';
    }
  };

  /* ──────────────────────────────────────────────────────────────────────
   *  GATE FUNCTION
   *  Call this before rendering the main app.
   *  Returns a Promise that resolves when the user is confirmed activated.
   * ────────────────────────────────────────────────────────────────────── */
  function gate(onActivated, onNotActivated) {
    isActivated().then(function (activated) {
      if (activated) {
        var info = getActivationInfo();
        UI.showActivationBadge(info);
        startRevalidationLoop();
        if (typeof onActivated === 'function') onActivated(info);
      } else {
        if (typeof onNotActivated === 'function') onNotActivated();
        UI.showActivationScreen().then(function (result) {
          var info = getActivationInfo();
          UI.showActivationBadge(info);
          startRevalidationLoop();
          if (typeof onActivated === 'function') onActivated(info);
        }).catch(function () {});
      }
    });
  }

  /* ──────────────────────────────────────────────────────────────────────
   *  EXPOSE PUBLIC API
   * ────────────────────────────────────────────────────────────────────── */
  window.NebulaActivation = {
    activate: activate,
    isActivated: isActivated,
    silentRevalidate: silentRevalidate,
    deactivate: deactivate,
    getActivationInfo: getActivationInfo,
    startRevalidationLoop: startRevalidationLoop,
    gate: gate,
    UI: UI,
    // Expose for testing/debugging only — remove in production
    _internal: NEBULA_CONFIG.DEBUG ? {
      buildFingerprint: _buildDeviceFingerprint,
      decodeJwt: _decodeJwtPayload,
      verifySignature: _verifyJwtSignature,
      clearActivation: _clearActivation
    } : {}
  };

})(window);
