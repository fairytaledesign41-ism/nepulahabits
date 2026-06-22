// ===== NEBULA SMART SERVICE WORKER (sw.js) =====
// v4 — Non-blocking caching + instant lifecycle activation for Vercel deployments.
//
// Caching strategies:
//   Navigation (page loads) → Network-First  (ensures fresh HTML on every reload)
//   CDN assets (fonts, libs) → Cache-First   (instant offline load after first visit)
//   Everything else          → Network-First  with stale cache fallback
//
// Lifecycle:
//   install  → pre-cache only the lean app shell; CDN assets warm in the background
//              so install never blocks or locks the UI thread.
//   activate → delete all stale caches, then clients.claim() to take control now.
//   skipWaiting in install + clients.claim in activate means every new Vercel
//   deployment is activated immediately — users never need a hard refresh.

const CACHE_NAME = 'nebula-v5-cache';

// Critical shell — must succeed for SW to install (kept tiny on purpose)
const SHELL_ASSETS = [
  './',
  './index.html'
];

// CDN assets — cached lazily in the background so install is never blocked
const CDN_ASSETS = [
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Tajawal:wght@400;500;700;800&family=Cairo:wght@400;500;600;700;800&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
  'https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js'
];

// ── INSTALL ───────────────────────────────────────────────────────────────────
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) {
        // Pre-cache only the tiny shell synchronously — this is what install waits on.
        return cache.addAll(SHELL_ASSETS);
      })
      .then(function() {
        // Warm CDN assets in the background; individual failures are silently ignored
        // so a slow CDN never delays or fails the SW install.
        caches.open(CACHE_NAME).then(function(cache) {
          CDN_ASSETS.forEach(function(url) {
            fetch(url, { mode: 'cors', credentials: 'omit' })
              .then(function(res) {
                if (res && res.ok) { cache.put(url, res); }
              })
              .catch(function() { /* non-critical, skip silently */ });
          });
        });

        // skipWaiting: the new SW takes over immediately on next Vercel deploy
        // without waiting for existing tabs to close.
        return self.skipWaiting();
      })
  );
});

// ── ACTIVATE ──────────────────────────────────────────────────────────────────
self.addEventListener('activate', function(event) {
  event.waitUntil(
    // Delete every cache version that isn't the current one
    caches.keys()
      .then(function(keys) {
        return Promise.all(
          keys
            .filter(function(key) { return key !== CACHE_NAME; })
            .map(function(key)   { return caches.delete(key);  })
        );
      })
      .then(function() {
        // Claim all open clients immediately so they benefit from the new SW
        // without needing to reload manually.
        return self.clients.claim();
      })
  );
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function(event) {
  var request = event.request;

  // Only intercept GET — pass all other methods through unchanged
  if (request.method !== 'GET') return;

  var url = request.url;

  // ── Strategy A: Navigation requests (HTML page loads) — Network-First ────
  // Always try the network first to get fresh HTML from Vercel.
  // Only fall back to the cached shell when completely offline.
  // IMPORTANT: strip query parameters (e.g. ?key=...) when matching the cache
  // so that personalised PWA launch URLs still resolve to the cached shell.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(function(res) {
          // Opportunistically refresh the cached shell entry (without ?key=)
          if (res && res.ok) {
            var clone = res.clone();
            caches.open(CACHE_NAME).then(function(c) { c.put(request, clone); });
          }
          return res;
        })
        .catch(function() {
          // Offline — try exact URL first, then fall back to the bare shell
          return caches.match(request).then(function(cached) {
            return cached || caches.match('./index.html');
          });
        })
    );
    return;
  }

  // ── Strategy B: CDN / static assets — Cache-First ────────────────────────
  // These files are versioned / content-addressed; serve from cache instantly
  // and update in the background only when online.
  var isCDN = (
    url.indexOf('fonts.googleapis.com')  !== -1 ||
    url.indexOf('fonts.gstatic.com')     !== -1 ||
    url.indexOf('cdnjs.cloudflare.com')  !== -1 ||
    url.indexOf('cdn.jsdelivr.net')      !== -1
  );

  if (isCDN) {
    event.respondWith(
      caches.match(request).then(function(cached) {
        if (cached) {
          // Serve from cache; refresh entry in the background (stale-while-revalidate)
          fetch(request, { mode: 'cors', credentials: 'omit' })
            .then(function(res) {
              if (res && res.ok) {
                caches.open(CACHE_NAME).then(function(c) { c.put(request, res); });
              }
            })
            .catch(function() {});
          return cached;
        }
        // Not cached yet — fetch and cache
        return fetch(request, { mode: 'cors', credentials: 'omit' })
          .then(function(res) {
            if (res && res.ok) {
              var clone = res.clone();
              caches.open(CACHE_NAME).then(function(c) { c.put(request, clone); });
            }
            return res;
          });
      })
    );
    return;
  }

  // ── Strategy C: All other requests — Network-First with cache fallback ────
  event.respondWith(
    fetch(request)
      .then(function(res) {
        if (res && res.ok) {
          var clone = res.clone();
          caches.open(CACHE_NAME).then(function(c) { c.put(request, clone); });
        }
        return res;
      })
      .catch(function() {
        return caches.match(request);
      })
  );
});
