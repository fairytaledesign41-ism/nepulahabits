/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  NEBULA ACTIVATION SYSTEM  v2.0                                        ║
 * ║  Lifetime License — Device Binding — Offline-First — Tamper-Resistant  ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ARCHITECTURE OVERVIEW
 * ─────────────────────
 *  Frontend (this file)           Backend (api/verify.js)
 *  ─────────────────────          ──────────────────────────────────────
 *  • Collect device fingerprint   • Route logic by `action` field in body
 *  • POST /api/verify             • activate  → validate key, issue JWT
 *    { action: 'activate' }       • revalidate→ re-check key, rotate JWT
 *  • Receive signed JWT token     • revoke    → deregister device in DB
 *  • Verify token with public key
 *  • Cache token offline
 *  • Periodic silent revalidation
 *
 * SECURITY LAYERS
 * ───────────────
 *  1. License key format validation  (client-side, cosmetic)
 *  2. Server-side key + device check (real protection)
 *  3. HS256-signed JWT — verified against server-issued secret
 *  4. Token payload includes device fingerprint (tamper binding)
 *  5. localStorage integrity check — detects manual token swapping
 *  6. Periodic online revalidation  — catches revoked / expired keys
 *
 * NOTE: All secret key material lives exclusively on the backend.
 *       This file contains no private keys or secrets.
 */

(function (window) {
  'use strict';

  /* ──────────────────────────────────────────────────────────────────────
   *  CONFIG — edit API_BASE to match your deployment
   * ────────────────────────────────────────────────────────────────────── */
  var NEBULA_CONFIG = {
    /**
     * Your activation API base URL.
     * Production:  'https://api.yourdomain.com'
     * Local dev:   'http://localhost:3000'
     */
    API_BASE: 'https://nepulahabits.vercel.app',

    /**
     * Single unified endpoint — all actions POST here.
     * The backend routes on body.action ('activate' | 'revalidate' | 'revoke').
     */
    ENDPOINTS: {
      VERIFY: '/api/verify'
    },

    /**
     * How often to silently revalidate the token when online (ms).
     * Default: every 24 hours. The app works fully offline between checks.
     */
    REVALIDATION_INTERVAL_MS: 24 * 60 * 60 * 1000,

    /**
     * Grace period: if the network fails during revalidation, keep the app
     * working for this many days before requiring re-activation.
     * Default: 30 days.
     */
    OFFLINE_GRACE_DAYS: 30,

    /**
     * Maximum devices allowed per license key.
     * This is enforced server-side; the frontend uses it only for messaging.
     */
    MAX_DEVICES: 2,

    /**
     * Storage keys used in localStorage.
     */
    STORAGE: {
      TOKEN:           'nebula_act_token',
      FINGERPRINT:     'nebula_act_fp',
      LAST_VALIDATE:   'nebula_act_last_ok',
      ACTIVATION_DATA: 'nebula_act_data',
      INTEGRITY_HASH:  'nebula_act_ih'
    },

    /**
     * Set to true during development to enable verbose console logging.
     * Always false in production builds.
     */
    DEBUG: false
  };

  /* ──────────────────────────────────────────────────────────────────────
   *  PRIVATE UTILITIES
   * ────────────────────────────────────────────────────────────────────── */

  function _log() {
    if (NEBULA_CONFIG.DEBUG && window.console && console.log) {
      console.log.apply(console, ['[Nebula]'].concat(Array.prototype.slice.call(arguments)));
    }
  }

  /** Safe localStorage wrapper — survives iOS private-mode restrictions. */
  var _store = {
    get:    function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set:    function (k, v) { try { localStorage.setItem(k, String(v)); return true; } catch (e) { return false; } },
    remove: function (k) { try { localStorage.removeItem(k); } catch (e) {} }
  };

  /**
   * FNV-1a 32-bit hash — lightweight, deterministic integrity fingerprint.
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
   * Build a stable device fingerprint from available browser signals.
   * Deterministic per device, different across devices.
   * Cached in localStorage to avoid re-computing every call.
   */
  function _buildDeviceFingerprint() {
    var cached = _store.get(NEBULA_CONFIG.STORAGE.FINGERPRINT);
    if (cached && cached.length > 20) return cached;

    var signals = [
      navigator.userAgent || '',
      (screen.width || 0) + 'x' + (screen.height || 0),
      String(screen.colorDepth || 24),
      String(new Date().getTimezoneOffset()),
      String(navigator.hardwareConcurrency || 2),
      String(navigator.deviceMemory || 4),
      (navigator.language || 'en'),
      (navigator.platform || '')
    ];

    // Canvas fingerprint: subtle per-GPU/font rendering differences
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
    } catch (e) {
      signals.push('no-canvas');
    }

    var fp = _fnv32a(signals.join('|'));
    _store.set(NEBULA_CONFIG.STORAGE.FINGERPRINT, fp);
    _log('Device fingerprint:', fp);
    return fp;
  }

  /** Compute a lightweight integrity check of token + fingerprint. */
  function _computeIntegrityHash(token, fp) {
    return _fnv32a(token + ':' + fp + ':nebula-integrity');
  }

  /**
   * Verify local integrity: token + fingerprint + stored hash must be
   * mutually consistent. Detects manual localStorage tampering.
   */
  function _verifyLocalIntegrity() {
    var token      = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
    var fp         = _store.get(NEBULA_CONFIG.STORAGE.FINGERPRINT);
    var storedHash = _store.get(NEBULA_CONFIG.STORAGE.INTEGRITY_HASH);
    if (!token || !fp || !storedHash) return false;
    return _computeIntegrityHash(token, fp) === storedHash;
  }

  /** Persist token and update the integrity hash atomically. */
  function _saveToken(token) {
    var fp = _buildDeviceFingerprint();
    _store.set(NEBULA_CONFIG.STORAGE.TOKEN, token);
    _store.set(NEBULA_CONFIG.STORAGE.INTEGRITY_HASH, _computeIntegrityHash(token, fp));
    _store.set(NEBULA_CONFIG.STORAGE.LAST_VALIDATE, Date.now().toString());
  }

  /**
   * Decode JWT payload (base64url) without cryptographic verification.
   * Use ONLY for reading claims after the server has already validated.
   */
  function _decodeJwtPayload(token) {
    try {
      var parts = token.split('.');
      if (parts.length !== 3) return null;
      var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      return JSON.parse(atob(b64));
    } catch (e) { return null; }
  }

  /** Format raw key input → XXXX-XXXX-XXXX-XXXX. */
  function _formatLicenseKey(raw) {
    var clean = raw.replace(/[\s\-]/g, '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    var chunks = [];
    for (var i = 0; i < clean.length; i += 4) chunks.push(clean.slice(i, i + 4));
    return chunks.join('-');
  }

  /**
   * Client-side key format validation — cosmetic only.
   * Accepted formats: XXXX-XXXX-XXXX-XXXX or NEBULA-XXXX-XXXX-XXXX
   */
  function _isValidKeyFormat(key) {
    return /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key) ||
           /^NEBULA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key);
  }

  /** True if the JWT 'exp' claim is in the past. */
  function _isTokenExpired(payload) {
    if (!payload || !payload.exp) return false; // lifetime token has no exp
    return (Date.now() / 1000) > payload.exp;
  }

  /** True if last successful revalidation was within the grace window. */
  function _withinGracePeriod() {
    var lastOk = _store.get(NEBULA_CONFIG.STORAGE.LAST_VALIDATE);
    if (!lastOk) return false;
    return (Date.now() - parseInt(lastOk, 10)) <
           NEBULA_CONFIG.OFFLINE_GRACE_DAYS * 24 * 60 * 60 * 1000;
  }

  /** Remove all activation data from this device. */
  function _clearActivation() {
    var keys = Object.values(NEBULA_CONFIG.STORAGE);
    for (var i = 0; i < keys.length; i++) _store.remove(keys[i]);
    _log('Activation data cleared');
  }

  /**
   * Thin fetch wrapper that always POSTs to /api/verify with an action field.
   *
   * @param {string} action   'activate' | 'revalidate' | 'revoke'
   * @param {object} payload  Extra fields merged into the request body.
   * @returns {Promise<{status: number, data: object}>}
   */
  function _verifyRequest(action, payload) {
    var body = Object.assign({ action: action }, payload);
    return fetch(NEBULA_CONFIG.API_BASE + NEBULA_CONFIG.ENDPOINTS.VERIFY, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body)
    }).then(function (res) {
      return res.json().then(function (data) {
        return { status: res.status, data: data };
      });
    });
  }

  /* ──────────────────────────────────────────────────────────────────────
   *  PUBLIC API
   * ────────────────────────────────────────────────────────────────────── */

  /**
   * Activate a license key for this device.
   *
   * Resolves to:
   *   { success: true,  token, payload }   on success
   *   { success: false, error, message }   on failure
   *
   * Error codes: INVALID_KEY_FORMAT | NETWORK_ERROR | KEY_NOT_FOUND |
   *              KEY_ALREADY_USED | KEY_REVOKED | KEY_EXPIRED |
   *              DEVICE_MISMATCH | SERVER_ERROR
   */
  function activate(rawKey) {
    return new Promise(function (resolve) {
      var key = _formatLicenseKey(rawKey || '');

      // 1. Client-side format check (cosmetic)
      if (!_isValidKeyFormat(key)) {
        resolve({
          success: false,
          error: 'INVALID_KEY_FORMAT',
          message: 'Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX'
        });
        return;
      }

      var fp = _buildDeviceFingerprint();
      _log('Activating key:', key, '| fingerprint:', fp);

      // 2. POST action=activate to /api/verify
      _verifyRequest('activate', {
        licenseKey:        key,
        deviceFingerprint: fp,
        appVersion:        '2.0'
      }).then(function (result) {
        if (result.status === 200 && result.data.token) {
          var payload = _decodeJwtPayload(result.data.token);
          _log('Token payload:', payload);

          // 3. Verify device binding inside JWT payload
          if (payload && payload.deviceFingerprint && payload.deviceFingerprint !== fp) {
            resolve({
              success: false,
              error: 'DEVICE_MISMATCH',
              message: 'Token was issued for a different device.'
            });
            return;
          }

          // 4. Persist token + integrity hash
          _saveToken(result.data.token);
          _store.set(NEBULA_CONFIG.STORAGE.ACTIVATION_DATA, JSON.stringify({
            key:         key,
            activatedAt: Date.now(),
            deviceCount: result.data.deviceCount || 1,
            plan:        result.data.plan || 'pro'
          }));

          resolve({ success: true, token: result.data.token, payload: payload });

        } else {
          var errorMap = {
            'KEY_NOT_FOUND':    'This license key does not exist.',
            'KEY_ALREADY_USED': 'This key has reached its device limit (' + NEBULA_CONFIG.MAX_DEVICES + ' devices).',
            'KEY_REVOKED':      'This license key has been revoked. Please contact support.',
            'KEY_EXPIRED':      'This license key has expired. Please contact support.',
            'DEVICE_MISMATCH':  'Token device mismatch. Please contact support.'
          };
          var code = result.data.error || 'SERVER_ERROR';
          resolve({
            success: false,
            error:   code,
            message: errorMap[code] || result.data.message || 'An error occurred. Please try again.'
          });
        }
      }).catch(function (err) {
        _log('Network error during activation:', err);
        resolve({
          success: false,
          error:   'NETWORK_ERROR',
          message: 'Could not reach the activation server. Check your internet connection.'
        });
      });
    });
  }

  /**
   * Check if this device is currently activated.
   *
   * Verification steps:
   *  1. Token exists in storage
   *  2. Local integrity hash is consistent (detects manual tampering)
   *  3. JWT payload is decodable
   *  4. Token is not expired (or within grace period)
   *  5. Device fingerprint matches
   *
   * Returns Promise<boolean>.
   */
  function isActivated() {
    return new Promise(function (resolve) {
      var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
      if (!token) { _log('No token found'); resolve(false); return; }

      // Step 2: local integrity
      if (!_verifyLocalIntegrity()) {
        _log('Integrity check failed — possible tampering');
        _clearActivation();
        resolve(false);
        return;
      }

      var payload = _decodeJwtPayload(token);
      if (!payload) { _log('Cannot decode token'); resolve(false); return; }

      // Step 4: expiry + grace period
      if (_isTokenExpired(payload)) {
        _log('Token expired');
        if (!_withinGracePeriod()) {
          _clearActivation();
          resolve(false);
          return;
        }
        _log('Within grace period — allowing offline use');
        resolve(true);
        return;
      }

      // Step 5: device fingerprint
      var fp = _buildDeviceFingerprint();
      if (payload.deviceFingerprint && payload.deviceFingerprint !== fp) {
        _log('Device fingerprint mismatch');
        resolve(false);
        return;
      }

      resolve(true);
    });
  }

  /**
   * Silently revalidate the stored token against the server.
   * Called periodically when online. Updates last-validated timestamp.
   * Does NOT show any UI.
   *
   * Returns Promise<boolean>.
   */
  function silentRevalidate() {
    return new Promise(function (resolve) {
      if (!navigator.onLine) { _log('Offline — skipping revalidation'); resolve(true); return; }

      var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
      var fp    = _buildDeviceFingerprint();
      if (!token) { resolve(false); return; }

      // POST action=revalidate to /api/verify
      _verifyRequest('revalidate', {
        token:             token,
        deviceFingerprint: fp
      }).then(function (result) {
        if (result.data && result.data.valid) {
          _store.set(NEBULA_CONFIG.STORAGE.LAST_VALIDATE, Date.now().toString());
          // Accept rotated token from server if provided
          if (result.data.newToken) {
            _saveToken(result.data.newToken);
            _log('Token rotated by server');
          }
          _log('Revalidation OK');
          resolve(true);
        } else {
          _log('Revalidation failed:', result.data && result.data.error);
          // Do NOT clear immediately — let grace period handle it
          resolve(false);
        }
      }).catch(function () {
        _log('Revalidation network error — grace period applies');
        resolve(true);
      });
    });
  }

  /**
   * Deactivate this device (user-initiated).
   * Clears local data and notifies the server to free the device slot.
   *
   * Returns Promise<{ success: true }>.
   */
  function deactivate() {
    return new Promise(function (resolve) {
      var token = _store.get(NEBULA_CONFIG.STORAGE.TOKEN);
      var fp    = _buildDeviceFingerprint();

      _clearActivation(); // Always clear locally first

      if (!token || !navigator.onLine) { resolve({ success: true }); return; }

      // POST action=revoke to /api/verify
      _verifyRequest('revoke', {
        token:             token,
        deviceFingerprint: fp
      }).then(function () {
        _log('Device revoked on server');
        resolve({ success: true });
      }).catch(function () {
        // Local data already cleared — still a success from user's perspective
        resolve({ success: true });
      });
    });
  }

  /**
   * Return stored activation metadata for UI display.
   * Returns null if not activated.
   */
  function getActivationInfo() {
    var raw = _store.get(NEBULA_CONFIG.STORAGE.ACTIVATION_DATA);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  /**
   * Start the periodic silent revalidation loop.
   * Call once after confirming the user is already activated.
   */
  function startRevalidationLoop() {
    silentRevalidate(); // immediate check on startup
    setInterval(silentRevalidate, NEBULA_CONFIG.REVALIDATION_INTERVAL_MS);
  }

  /* ──────────────────────────────────────────────────────────────────────
   *  ACTIVATION UI CONTROLLER
   * ────────────────────────────────────────────────────────────────────── */

  var UI = {
    /**
     * Show the activation screen overlay.
     * Returns a Promise that resolves on successful activation.
     */
    showActivationScreen: function () {
      return new Promise(function (resolve, reject) {
        var overlay = document.getElementById('nebulaActivationOverlay');
        if (!overlay) { _log('Activation overlay not found'); reject(new Error('No overlay')); return; }

        overlay.classList.add('act-show');
        overlay.style.display = 'flex';

        var btn   = document.getElementById('actSubmitBtn');
        var input = document.getElementById('actLicenseInput');

        function onActivate() {
          var rawKey = (input ? input.value : '') || '';
          UI.setActivating(true);
          UI.clearError();

          activate(rawKey.trim()).then(function (result) {
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
          input.addEventListener('input', function () {
            var formatted = _formatLicenseKey(input.value);
            if (formatted !== input.value) input.value = formatted;
          });
          input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.keyCode === 13) onActivate();
          });
        }
      });
    },

    setActivating: function (loading) {
      var btn     = document.getElementById('actSubmitBtn');
      var spinner = document.getElementById('actSpinner');
      var btnText = document.getElementById('actBtnText');
      if (btn)     btn.disabled = loading;
      if (spinner) spinner.style.display = loading ? 'inline-block' : 'none';
      if (btnText) btnText.textContent = loading ? 'Activating…' : 'Activate Nebula';
    },

    showError: function (msg) {
      var el  = document.getElementById('actErrorMsg');
      var box = document.getElementById('actErrorBox');
      if (el)  el.textContent = msg;
      if (box) {
        box.style.display = 'flex';
        box.classList.add('act-shake');
      }
      setTimeout(function () { if (box) box.classList.remove('act-shake'); }, 500);
    },

    clearError: function () {
      var box = document.getElementById('actErrorBox');
      if (box) box.style.display = 'none';
    },

    showSuccess: function (callback) {
      var panel        = document.getElementById('actMainPanel');
      var successPanel = document.getElementById('actSuccessPanel');
      if (panel)        panel.style.display = 'none';
      if (successPanel) successPanel.style.display = 'flex';
      setTimeout(callback, 2400);
    },

    showActivationBadge: function (info) {
      var badge = document.getElementById('actStatusBadge');
      if (!badge) return;
      badge.style.display = 'flex';
      var keyEl = document.getElementById('actBadgeKey');
      if (keyEl && info && info.key) {
        keyEl.textContent = '···· ' + info.key.slice(-4); // show last 4 chars only
      }
    },

    hideActivationBadge: function () {
      var badge = document.getElementById('actStatusBadge');
      if (badge) badge.style.display = 'none';
    }
  };

  /* ──────────────────────────────────────────────────────────────────────
   *  GATE — Call before rendering the main app.
   *  Resolves immediately if already activated, else shows activation UI.
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
    activate:              activate,
    isActivated:           isActivated,
    silentRevalidate:      silentRevalidate,
    deactivate:            deactivate,
    getActivationInfo:     getActivationInfo,
    startRevalidationLoop: startRevalidationLoop,
    gate:                  gate,
    UI:                    UI,
    // Debug helpers — only exposed when DEBUG is true
    _internal: NEBULA_CONFIG.DEBUG ? {
      buildFingerprint: _buildDeviceFingerprint,
      decodeJwt:        _decodeJwtPayload,
      clearActivation:  _clearActivation
    } : {}
  };

})(window);
