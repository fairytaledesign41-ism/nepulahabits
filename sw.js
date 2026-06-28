// ===== NEBULA SMART SERVICE WORKER (sw.js) =====
// v5 — Tiered auth support: preserves ?key= query strings, posts license key
//      to page via postMessage, offline-first for the app shell.
//
// Key changes vs v4:
//   • Navigation requests: strips query string ONLY for cache lookup, but
//     forwards the full original request to the network — so ?key= is never lost.
//   • After serving a cached shell, SW reads the `key` param from the request
//     URL and posts it back to the page client via postMessage so Tier 0.5 works.
//   • Cache-busting: CACHE_NAME bumped to v5 so stale v4 entries are purged.

var CACHE_NAME = 'nebula-v5-cache';

// Critical shell — must succeed for SW to install (kept tiny on purpose)
var SHELL_ASSETS = [
  './',
  './index.html'
];

// CDN assets — cached lazily in the background so install is never blocked
var CDN_ASSETS = [
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Tajawal:wght@400;500;700;800&family=Cairo:wght@400;500;600;700;800&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
  'https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js',
  'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js'
];

// ── INSTALL ───────────────────────────────────────────────────────────────────
self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function (cache) {
        return cache.addAll(SHELL_ASSETS);
      })
      .then(function () {
        // Warm CDN assets in the background; individual failures are silently ignored
        caches.open(CACHE_NAME).then(function (cache) {
          CDN_ASSETS.forEach(function (url) {
            fetch(url, { mode: 'cors', credentials: 'omit' })
              .then(function (res) {
                if (res && res.ok) { cache.put(url, res); }
              })
              .catch(function () { /* non-critical */ });
          });
        });

        return self.skipWaiting();
      })
  );
});

// ── ACTIVATE ──────────────────────────────────────────────────────────────────
self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(
          keys
            .filter(function (key) { return key !== CACHE_NAME; })
            .map(function (key) { return caches.delete(key); })
        );
      })
      .then(function () {
        return self.clients.claim();
      })
  );
});

// ── MESSAGE: page can request the SW to echo back a stored key ────────────────
// The page posts { type: 'GET_KEY_FROM_URL' } and SW replies with any ?key=
// param it extracted from the most recent navigation request.
var _lastKeyFromUrl = null;

self.addEventListener('message', function (event) {
  if (!event.data) return;

  if (event.data.type === 'GET_KEY_FROM_URL') {
    if (event.source && _lastKeyFromUrl) {
      event.source.postMessage({ type: 'SW_KEY_RESPONSE', key: _lastKeyFromUrl });
    }
  }
});

// ── HELPER: extract `?key=` from a URL string ─────────────────────────────────
function extractKeyParam(urlString) {
  try {
    var url = new URL(urlString);
    return url.searchParams.get('key') || null;
  } catch (e) {
    // Fallback for browsers without URL constructor in SW context
    var match = urlString.match(/[?&]key=([^&]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  }
}

// ── HELPER: cache key for navigation (strip query string so we always
//    match the shell regardless of ?key= or ?shortcut= params) ─────────────────
function navigationCacheKey(request) {
  try {
    var url = new URL(request.url);
    // Only strip query params; keep origin + pathname
    return new Request(url.origin + url.pathname);
  } catch (e) {
    return request;
  }
}

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function (event) {
  var request = event.request;

  // Only intercept GET — pass all other methods through unchanged
  if (request.method !== 'GET') return;

  var url = request.url;

  // ── Strategy A: Navigation requests (HTML page loads) — Network-First ────
  // • Always try network first to get fresh HTML from the host.
  // • Serve cached shell as offline fallback.
  // • Extract ?key= and stash it so the page can ask for it via postMessage.
  // • Cache the response under the path-only key (no query string) so future
  //   offline loads of ANY ?key= URL still hit the shell cache.
  if (request.mode === 'navigate') {
    // Capture the key BEFORE the async respond chain
    var keyParam = extractKeyParam(url);
    if (keyParam) {
      _lastKeyFromUrl = keyParam;
      // Broadcast to any already-open clients immediately
      self.clients.matchAll({ type: 'window' }).then(function (clients) {
        clients.forEach(function (client) {
          client.postMessage({ type: 'SW_KEY_BROADCAST', key: keyParam });
        });
      });
    }

    event.respondWith(
      fetch(request)
        .then(function (res) {
          if (res && res.ok) {
            // Cache under path-only key so offline works for all query variants
            var cacheKey = navigationCacheKey(request);
            var clone = res.clone();
            caches.open(CACHE_NAME).then(function (c) { c.put(cacheKey, clone); });
          }
          return res;
        })
        .catch(function () {
          // Offline — serve the cached shell; the key will come from cookie/LS
          var cacheKey = navigationCacheKey(request);
          return caches.match(cacheKey)
            .then(function (cached) {
              return cached || caches.match('./index.html');
            });
        })
    );
    return;
  }

  // ── Strategy B: CDN / static assets — Cache-First ────────────────────────
  var isCDN = (
    url.indexOf('fonts.googleapis.com') !== -1 ||
    url.indexOf('fonts.gstatic.com') !== -1 ||
    url.indexOf('cdnjs.cloudflare.com') !== -1 ||
    url.indexOf('cdn.jsdelivr.net') !== -1
  );

  if (isCDN) {
    event.respondWith(
      caches.match(request).then(function (cached) {
        if (cached) {
          // Stale-while-revalidate
          fetch(request, { mode: 'cors', credentials: 'omit' })
            .then(function (res) {
              if (res && res.ok) {
                caches.open(CACHE_NAME).then(function (c) { c.put(request, res); });
              }
            })
            .catch(function () {});
          return cached;
        }
        return fetch(request, { mode: 'cors', credentials: 'omit' })
          .then(function (res) {
            if (res && res.ok) {
              var clone = res.clone();
              caches.open(CACHE_NAME).then(function (c) { c.put(request, clone); });
            }
            return res;
          });
      })
    );
    return;
  }

  // ── Strategy C: All other requests — Network-First with cache fallback ────
  // Skip caching Supabase API calls — they must always go to the network
  if (url.indexOf('supabase.co') !== -1) {
    return; // Let the browser handle it natively (no SW interception)
  }

  event.respondWith(
    fetch(request)
      .then(function (res) {
        if (res && res.ok) {
          var clone = res.clone();
          caches.open(CACHE_NAME).then(function (c) { c.put(request, clone); });
        }
        return res;
      })
      .catch(function () {
        return caches.match(request);
      })
  );
});
