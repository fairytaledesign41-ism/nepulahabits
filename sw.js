// ===== NEBULA SERVICE WORKER (sw.js) =====
// v7 — Matches the URL-first, zero-network-if-cached activation system.
//
// Why this version is simple:
//   The page (index.html) now resolves the license key in this order:
//   URL ?key= (always wins) → Cookie → sessionStorage → localStorage,
//   and a cached key is trusted with NO network call at all. The
//   browser ALWAYS keeps the original ?key= in window.location.search
//   for as long as that tab/navigation is open — the Service Worker
//   does not need to intercept, extract, or relay that param via
//   postMessage. Each unique ?key=... URL is just a normal navigation;
//   the SW's job is only to make sure the app shell loads instantly,
//   online or offline, regardless of which key is in the URL.
//
// What this file still does:
//   • Caches the app shell (index.html) so the app loads offline.
//   • NEVER strips the query string from the actual navigation request
//     that's sent to the network — ?key=... reaches the page exactly
//     as typed, every time, online or offline.
//   • Caches the shell under a path-only key so ANY ?key=... variant of
//     the URL still resolves to the same offline shell — every unique
//     key is treated as a valid session because the PAGE (not the SW)
//     is what reads and trusts that key.
//   • Cache-first for CDN/static assets, network-first with fallback for
//     everything else, and never intercepts Supabase API calls.

var CACHE_NAME = 'nebula-v9-cache';

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

// ── HELPER: cache key for navigation (strip query string so we always
//    match the shell regardless of ?key= or ?shortcut= params) ─────────────────
// IMPORTANT: this ONLY affects the key used to read/write the cache.
// The actual `fetch(request)` call below always uses the original,
// unmodified `request` — so the network always sees the real ?key=...
function navigationCacheKey(request) {
  try {
    var url = new URL(request.url);
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
  // • Always try network first to get fresh HTML, WITH the full original
  //   URL (including ?key=...) — nothing is stripped before this fetch.
  // • Serve the cached shell as an offline fallback.
  // • Cache the response under a path-only key (no query string) so
  //   future offline loads of ANY ?key=... URL still hit the shell cache.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(function (res) {
          if (res && res.ok) {
            var cacheKey = navigationCacheKey(request);
            var clone = res.clone();
            caches.open(CACHE_NAME).then(function (c) { c.put(cacheKey, clone); });
          }
          return res;
        })
        .catch(function () {
          // Offline — serve the cached shell. The page itself reads
          // ?key= straight from window.location.search, so the key
          // survives even though we're serving a path-only cache entry.
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
