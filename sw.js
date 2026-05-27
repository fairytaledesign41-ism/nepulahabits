// ===== NEBULA SMART SERVICE WORKER (sw.js) — Mobile-Fixed v4 =====
const CACHE_NAME = 'nebula-v4-cache';

// Derive the base path dynamically so this works on GitHub Pages subdirectories
// e.g. https://user.github.io/repo/ → base = '/repo/'
const BASE = self.registration.scope;

// Only cache the app shell itself; CDN resources are fetched with network-first
// and cached individually so a single CDN failure won't block SW install.
const APP_SHELL = [
  BASE,
  BASE + 'index.html'
];

const CDN_ASSETS = [
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Tajawal:wght@400;500;700;800&family=Cairo:wght@400;500;600;700;800&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
  'https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js'
];

// Install: cache the app shell first (must succeed), then attempt CDN cache (best-effort)
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      // Cache app shell — required
      return cache.addAll(APP_SHELL).then(function() {
        // Cache CDN assets — best-effort, failures are silently ignored
        var cdnPromises = CDN_ASSETS.map(function(url) {
          return fetch(url, { mode: 'cors', credentials: 'omit' })
            .then(function(res) {
              if (res && res.ok) return cache.put(url, res);
            })
            .catch(function() { /* CDN unavailable — skip silently */ });
        });
        return Promise.all(cdnPromises);
      });
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

// Activate: clean up old caches
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.map(function(k) {
          if (k !== CACHE_NAME) return caches.delete(k);
        })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// Fetch: cache-first for same-origin + CDN, network-first fallback
self.addEventListener('fetch', function(e) {
  // Only handle GET requests
  if (e.request.method !== 'GET') return;

  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;

      return fetch(e.request).then(function(networkRes) {
        // Cache a clone of successful responses for future offline use
        if (networkRes && networkRes.ok && networkRes.status === 200) {
          var resClone = networkRes.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(e.request, resClone);
          });
        }
        return networkRes;
      }).catch(function() {
        // Network failed — for navigation requests fall back to the cached shell
        if (e.request.mode === 'navigate') {
          return caches.match(BASE + 'index.html');
        }
      });
    })
  );
});
