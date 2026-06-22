// ===== NEBULA SMART SERVICE WORKER (sw.js) =====
// v6 — Correct offline PWA support with ?key= licence URL handling.
//
// Key fix: navigation requests with ?key=... are served from the cached
// index.html shell so the PWA opens correctly offline.  The key is carried
// into the page via sessionStorage (written by the <head> inline script
// before this SW intercepts anything), not via the URL — so the activation
// logic always has access to it.
//
// Caching strategies:
//   Navigation (HTML)  → Network-First, cache-shell fallback (strips ?key=)
//   CDN assets         → Cache-First with background revalidation
//   Everything else    → Network-First with stale cache fallback

const CACHE_NAME = 'nebula-v6-cache';

const SHELL_ASSETS = [
  './',
  './index.html',
  './manifest.json'
];

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
        return cache.addAll(SHELL_ASSETS);
      })
      .then(function() {
        // Warm CDN assets in background — failures silently ignored
        caches.open(CACHE_NAME).then(function(cache) {
          CDN_ASSETS.forEach(function(url) {
            fetch(url, { mode: 'cors', credentials: 'omit' })
              .then(function(res) {
                if (res && res.ok) cache.put(url, res);
              })
              .catch(function() {});
          });
        });
        return self.skipWaiting();
      })
  );
});

// ── ACTIVATE ──────────────────────────────────────────────────────────────────
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys()
      .then(function(keys) {
        return Promise.all(
          keys
            .filter(function(key) { return key !== CACHE_NAME; })
            .map(function(key)   { return caches.delete(key);  })
        );
      })
      .then(function() { return self.clients.claim(); })
  );
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function(event) {
  var request = event.request;
  if (request.method !== 'GET') return;

  var url = request.url;

  // ── Strategy A: Navigation (HTML page loads) ─────────────────────────────
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(function(res) {
          if (res && res.ok) {
            // Cache BOTH the exact URL (with ?key=) and the bare shell
            var clone1 = res.clone();
            var clone2 = res.clone();
            caches.open(CACHE_NAME).then(function(c) {
              c.put(request, clone1);           // exact URL (e.g. index.html?key=ABC)
              c.put('./index.html', clone2);    // bare shell fallback
            });
          }
          return res;
        })
        .catch(function() {
          // Offline fallback:
          // 1. Try exact cached URL (e.g. index.html?key=ABC) — covers home screen PWA
          // 2. Fall back to bare cached shell
          return caches.match(request)
            .then(function(cached) {
              return cached || caches.match('./index.html');
            });
        })
    );
    return;
  }

  // ── Strategy B: CDN / static assets — Cache-First ───────────────────────
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
          // Serve from cache; revalidate in background
          fetch(request, { mode: 'cors', credentials: 'omit' })
            .then(function(res) {
              if (res && res.ok)
                caches.open(CACHE_NAME).then(function(c) { c.put(request, res); });
            })
            .catch(function() {});
          return cached;
        }
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

  // ── Strategy C: Everything else — Network-First ──────────────────────────
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
