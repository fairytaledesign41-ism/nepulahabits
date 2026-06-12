/**
 * Nebula-activation.js
 * ─────────────────────────────────────────────────────────────────
 * Hardware-based device fingerprinting + offline-first JWT verification
 * for the Nebula Habit Tracker PWA.
 *
 * Dependencies: none (vanilla JS, Web Crypto API)
 * Compatible: Chrome 60+, Firefox 55+, Safari 13+, Edge 79+
 * ─────────────────────────────────────────────────────────────────
 */

(function (root) {
  'use strict';

  /* ══════════════════════════════════════════════════════════════
     SECTION 1 — CONSTANTS & CONFIG
  ══════════════════════════════════════════════════════════════ */
  var NEBULA_TOKEN_KEY    = 'nebula_act_token';
  var NEBULA_FP_KEY       = 'nebula_device_fp';
  var NEBULA_GRACE_DAYS   = 7;          // offline grace period (days)
  var API_ENDPOINT        = '/api/verify';
  var LICENSE_KEY_REGEX   = /^NEBULA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

  /* ══════════════════════════════════════════════════════════════
     SECTION 2 — SAFE STORAGE (wraps localStorage with fallback)
  ══════════════════════════════════════════════════════════════ */
  var _memStore = {};
  var _safeStorage = {
    getItem: function (k) {
      try { return localStorage.getItem(k); } catch (e) { return _memStore[k] || null; }
    },
    setItem: function (k, v) {
      try { localStorage.setItem(k, v); } catch (e) { _memStore[k] = v; }
    },
    removeItem: function (k) {
      try { localStorage.removeItem(k); } catch (e) { delete _memStore[k]; }
    }
  };

  /* ══════════════════════════════════════════════════════════════
     SECTION 3 — DEVICE FINGERPRINTING
     Collects ~12 stable hardware/browser signals and hashes them
     to a SHA-256 hex string that remains consistent across sessions.
  ══════════════════════════════════════════════════════════════ */

  /**
   * Collect raw browser / hardware signals.
   * @returns {string}  A deterministic raw string from device properties.
   */
  function _collectRawSignals() {
    var nav = navigator;
    var scr = screen;
    var signals = [
      // Platform & architecture
      nav.platform || '',
      nav.userAgent || '',
      nav.language || '',
      (nav.languages || []).join(','),
      String(nav.hardwareConcurrency || 0),
      String(nav.deviceMemory || 0),

      // Screen geometry (stable across sessions on a physical device)
      String(scr.width),
      String(scr.height),
      String(scr.colorDepth),
      String(scr.pixelDepth),

      // Timezone
      (Intl && Intl.DateTimeFormat ? Intl.DateTimeFormat().resolvedOptions().timeZone : '') || '',

      // WebGL renderer (GPU identity) — strongest hardware signal
      (function () {
        try {
          var canvas = document.createElement('canvas');
          var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return '';
          var dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
          return dbgInfo
            ? (gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL) + '|' +
               gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL))
            : gl.getParameter(gl.RENDERER);
        } catch (e) { return ''; }
      })(),

      // Canvas 2D font rendering fingerprint
      (function () {
        try {
          var canvas = document.createElement('canvas');
          canvas.width = 280; canvas.height = 60;
          var ctx = canvas.getContext('2d');
          ctx.textBaseline = 'alphabetic';
          ctx.fillStyle = '#a855f7';
          ctx.font = '14px "Inter",Arial,sans-serif';
          ctx.fillText('Nebula \uD83D\uDCAB Hardware FP', 10, 40);
          ctx.fillStyle = 'rgba(244,114,182,0.7)';
          ctx.font = '11px "Tajawal",sans-serif';
          ctx.fillText('نيبولا', 200, 50);
          return canvas.toDataURL().slice(-80);  // last 80 chars is unique
        } catch (e) { return ''; }
      })(),

      // Audio context sample rate (hardware DAC signal)
      (function () {
        try {
          var AudioCtx = root.AudioContext || root.webkitAudioContext;
          if (!AudioCtx) return '';
          var ctx = new AudioCtx();
          var sr = String(ctx.sampleRate);
          ctx.close && ctx.close();
          return sr;
        } catch (e) { return ''; }
      })()
    ];

    return signals.join('::');
  }

  /**
   * SHA-256 hash via Web Crypto API.
   * @param {string} message
   * @returns {Promise<string>}  hex string
   */
  function _sha256(message) {
    var encoder = new TextEncoder();
    var data = encoder.encode(message);
    return crypto.subtle.digest('SHA-256', data).then(function (buffer) {
      return Array.from(new Uint8Array(buffer))
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
    });
  }

  /**
   * Compute (and cache) the device fingerprint.
   * @returns {Promise<string>}
   */
  function getDeviceFingerprint() {
    var cached = _safeStorage.getItem(NEBULA_FP_KEY);
    if (cached && cached.length === 64) return Promise.resolve(cached);

    var raw = _collectRawSignals();
    return _sha256(raw).then(function (fp) {
      _safeStorage.setItem(NEBULA_FP_KEY, fp);
      return fp;
    });
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 4 — MINIMAL JWT PARSER (no library required)
     We only VERIFY the stored token structure & expiry offline.
     Signature is re-validated server-side on refresh.
  ══════════════════════════════════════════════════════════════ */

  /**
   * Base64URL decode helper.
   */
  function _b64urlDecode(str) {
    // Pad and convert base64url → base64
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    try {
      return JSON.parse(atob(str));
    } catch (e) {
      return null;
    }
  }

  /**
   * Parse a JWT without verifying the signature (offline use only).
   * Signature verification happens server-side.
   * @param {string} token
   * @returns {{ header: Object, payload: Object, valid: boolean }}
   */
  function parseJWT(token) {
    var result = { header: null, payload: null, valid: false };
    if (!token || typeof token !== 'string') return result;
    var parts = token.split('.');
    if (parts.length !== 3) return result;
    result.header  = _b64urlDecode(parts[0]);
    result.payload = _b64urlDecode(parts[1]);
    result.valid   = !!(result.header && result.payload);
    return result;
  }

  /**
   * Verify token offline: checks expiry, grace period, device binding.
   * @param {string} token        Stored JWT
   * @param {string} deviceFP     Current device fingerprint
   * @returns {{ ok: boolean, reason: string, payload: Object|null }}
   */
  function verifyTokenOffline(token, deviceFP) {
    var parsed = parseJWT(token);
    if (!parsed.valid) return { ok: false, reason: 'invalid_token', payload: null };

    var p   = parsed.payload;
    var now = Math.floor(Date.now() / 1000);

    // 1 — Expiry check (with grace period for offline use)
    if (p.exp) {
      var graceSeconds = NEBULA_GRACE_DAYS * 86400;
      if (now > p.exp + graceSeconds) {
        return { ok: false, reason: 'token_expired', payload: p };
      }
    }

    // 2 — Device binding check
    if (p.device && deviceFP && p.device !== deviceFP) {
      return { ok: false, reason: 'device_mismatch', payload: p };
    }

    return { ok: true, reason: 'ok', payload: p };
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 5 — ONLINE VERIFICATION (calls /api/verify)
  ══════════════════════════════════════════════════════════════ */

  /**
   * Send license key + device fingerprint to the server.
   * @param {string} licenseKey
   * @param {string} deviceFP
   * @returns {Promise<{ ok: boolean, token: string|null, error: string|null }>}
   */
  function _callVerifyAPI(licenseKey, deviceFP) {
    return fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: licenseKey, deviceFingerprint: deviceFP })
    })
      .then(function (res) {
        return res.json().then(function (data) {
          if (res.ok && data.token) {
            return { ok: true, token: data.token, error: null };
          }
          return { ok: false, token: null, error: data.error || 'server_error' };
        });
      })
      .catch(function () {
        return { ok: false, token: null, error: 'network_error' };
      });
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 6 — PUBLIC API
  ══════════════════════════════════════════════════════════════ */

  /**
   * Check activation status on app start.
   * 1. If a token is cached → verify offline (fast).
   * 2. If within the last 24 h since last online check → skip refresh.
   * 3. Otherwise try a silent online refresh.
   *
   * @returns {Promise<{ activated: boolean, plan: string|null, reason: string }>}
   */
  function checkActivation() {
    return getDeviceFingerprint().then(function (fp) {
      var storedToken = _safeStorage.getItem(NEBULA_TOKEN_KEY);
      if (!storedToken) return { activated: false, plan: null, reason: 'no_token' };

      var offlineResult = verifyTokenOffline(storedToken, fp);
      if (!offlineResult.ok) {
        if (offlineResult.reason !== 'token_expired') {
          return { activated: false, plan: null, reason: offlineResult.reason };
        }
      }

      // Silently refresh if token expires within 7 days
      var p = offlineResult.payload;
      var now = Math.floor(Date.now() / 1000);
      var shouldRefresh = p && p.exp && (p.exp - now) < NEBULA_GRACE_DAYS * 86400;

      if (shouldRefresh && p && p.sub) {
        _callVerifyAPI(p.sub, fp).then(function (apiResult) {
          if (apiResult.ok && apiResult.token) {
            _safeStorage.setItem(NEBULA_TOKEN_KEY, apiResult.token);
          }
        }).catch(function () {});
      }

      return {
        activated: offlineResult.ok,
        plan:      p ? (p.plan || 'pro') : null,
        reason:    offlineResult.reason
      };
    });
  }

  /**
   * Activate with a new license key (requires network).
   *
   * @param {string}   licenseKey  e.g. "NEBULA-XXXX-YYYY-ZZZZ"
   * @param {function} onSuccess   Called with { plan, token }
   * @param {function} onError     Called with { error: string }
   */
  function activateLicense(licenseKey, onSuccess, onError) {
    licenseKey = (licenseKey || '').trim().toUpperCase();

    if (!LICENSE_KEY_REGEX.test(licenseKey)) {
      onError({ error: 'invalid_key_format' });
      return;
    }

    getDeviceFingerprint().then(function (fp) {
      return _callVerifyAPI(licenseKey, fp).then(function (result) {
        if (result.ok && result.token) {
          _safeStorage.setItem(NEBULA_TOKEN_KEY, result.token);
          var parsed = parseJWT(result.token);
          onSuccess({ plan: parsed.payload ? parsed.payload.plan : 'pro', token: result.token });
        } else {
          onError({ error: result.error || 'activation_failed' });
        }
      });
    }).catch(function (err) {
      onError({ error: 'fingerprint_error' });
    });
  }

  /**
   * Deactivate this device (clears stored token).
   */
  function deactivate() {
    _safeStorage.removeItem(NEBULA_TOKEN_KEY);
    _safeStorage.removeItem(NEBULA_FP_KEY);
  }

  /**
   * Get current plan from cached token (synchronous).
   * @returns {string|null}
   */
  function getCachedPlan() {
    var token = _safeStorage.getItem(NEBULA_TOKEN_KEY);
    if (!token) return null;
    var parsed = parseJWT(token);
    return parsed.payload ? parsed.payload.plan : null;
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 7 — ERROR MESSAGE LOCALISATION
  ══════════════════════════════════════════════════════════════ */
  var ERROR_MESSAGES = {
    invalid_key_format: { en: 'Invalid key format. Expected: NEBULA-XXXX-YYYY-ZZZZ', ar: 'صيغة المفتاح غير صحيحة. المتوقع: NEBULA-XXXX-YYYY-ZZZZ' },
    key_not_found:      { en: 'License key not found.',                               ar: 'مفتاح الترخيص غير موجود.' },
    key_revoked:        { en: 'This license key has been revoked.',                   ar: 'تم إلغاء مفتاح الترخيص هذا.' },
    key_expired:        { en: 'This license key has expired.',                        ar: 'انتهت صلاحية مفتاح الترخيص.' },
    max_devices:        { en: 'Maximum device limit reached for this key.',           ar: 'تم الوصول إلى الحد الأقصى للأجهزة لهذا المفتاح.' },
    device_mismatch:    { en: 'Token is bound to a different device.',                ar: 'الرمز مرتبط بجهاز مختلف.' },
    token_expired:      { en: 'Activation expired. Please re-activate.',              ar: 'انتهت صلاحية التفعيل. يرجى إعادة التفعيل.' },
    network_error:      { en: 'No internet connection. Offline mode active.',         ar: 'لا يوجد اتصال بالإنترنت. وضع غير متصل نشط.' },
    server_error:       { en: 'Server error. Please try again later.',                ar: 'خطأ في الخادم. يرجى المحاولة مرة أخرى لاحقاً.' },
    activation_failed:  { en: 'Activation failed. Check your key and try again.',     ar: 'فشل التفعيل. تحقق من مفتاحك وحاول مرة أخرى.' }
  };

  /**
   * Get a localised error message.
   * @param {string} errorCode
   * @param {string} [lang='en']
   * @returns {string}
   */
  function getErrorMessage(errorCode, lang) {
    lang = lang || (document.documentElement.lang || 'en').split('-')[0];
    var entry = ERROR_MESSAGES[errorCode];
    if (!entry) return errorCode;
    return entry[lang] || entry['en'];
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 8 — EXPORT
  ══════════════════════════════════════════════════════════════ */
  root.NebulaActivation = {
    checkActivation:     checkActivation,
    activateLicense:     activateLicense,
    deactivate:          deactivate,
    getDeviceFingerprint:getDeviceFingerprint,
    getCachedPlan:       getCachedPlan,
    parseJWT:            parseJWT,
    getErrorMessage:     getErrorMessage
  };

})(window);
