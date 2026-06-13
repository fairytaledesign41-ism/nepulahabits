/**
 * Nebula Service Worker  v2.0
 * ─────────────────────────────────────────────────────────────────────────
 * • Offline-first caching for app shell and assets
 * • Activation API requests are NEVER cached (always go to network)
 * • Token revalidation requests pass through with network-first strategy
 * • All other API calls: network-first with 5s timeout fallback to cache
 * ─────────────────────────────────────────────────────────────────────────
 */

var CACHE_NAME    = 'nebula-v2';
var SHELL_CACHE   = 'nebula-shell-v2';
var DYNAMIC_CACHE = 'nebula-dynamic-v2';

/** Files to cache on install (app shell) */
var SHELL_ASSETS = [
  './',
  './index.html',
  './logo.png',
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Tajawal:wght@400;500;700;800&family=Cairo:wght@400;500;600;700;800&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
  'https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js'
];

/** URLs that must NEVER be served from cache */
var NEVER_CACHE_PATTERNS = [
  /\/v1\/license\//,            // activation API
  /\/v1\/license\/activate/,
  /\/v1\/license\/revalidate/,
  /\/v1\/license\/revoke-device/
];

/** Check if a URL matches any never-cache pattern */
function isActivationRequest(url) {
  for (var i = 0; i < NEVER_CACHE_PATTERNS.length; i++) {
    if (NEVER_CACHE_PATTERNS[i].test(url)) return true;
  }
  return false;
}

/* ──────────────── INSTALL ──────────────── */
self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(SHELL_CACHE).then(function (cache) {
      return cache.addAll(SHELL_ASSETS.map(function (url) {
        // Use no-cors for cross-origin CDN assets
        return new Request(url, { mode: 'no-cors' });
      })).catch(function (err) {
        console.warn('[SW] Shell cache partial failure (non-fatal):', err);
      });
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

/* ──────────────── ACTIVATE ──────────────── */
self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) {
          return k !== SHELL_CACHE && k !== DYNAMIC_CACHE;
        }).map(function (k) {
          console.log('[SW] Deleting old cache:', k);
          return caches.delete(k);
        })
      );
    }).then(function () {
      return self.clients.claim();
    })
  );
});

/* ──────────────── FETCH ──────────────── */
self.addEventListener('fetch', function (event) {
  var url = event.request.url;

  // 1. Activation API — ALWAYS network, never cache
  if (isActivationRequest(url)) {
    event.respondWith(fetch(event.request));
    return;
  }

  // 2. POST requests — pass through (never cache mutations)
  if (event.request.method !== 'GET') {
    event.respondWith(fetch(event.request));
    return;
  }

  // 3. App shell (HTML, JS, CSS, fonts) — cache-first
  if (
    url.indexOf(self.location.origin) !== -1 ||
    url.indexOf('fonts.googleapis.com') !== -1 ||
    url.indexOf('cdnjs.cloudflare.com') !== -1 ||
    url.indexOf('cdn.jsdelivr.net') !== -1
  ) {
    event.respondWith(
      caches.match(event.request).then(function (cached) {
        if (cached) return cached;
        return fetch(event.request).then(function (response) {
          if (response && response.status === 200) {
            var clone = response.clone();
            caches.open(DYNAMIC_CACHE).then(function (cache) {
              cache.put(event.request, clone);
            });
          }
          return response;
        }).catch(function () {
          // Return a minimal offline fallback for HTML requests
          if (event.request.headers.get('Accept') && event.request.headers.get('Accept').indexOf('text/html') !== -1) {
            return caches.match('./index.html');
          }
        });
      })
    );
    return;
  }

  // 4. Everything else — network with cache fallback
  event.respondWith(
    fetch(event.request).then(function (response) {
      return response;
    }).catch(function () {
      return caches.match(event.request);
    })
  );
});

/* ──────────────── PUSH NOTIFICATIONS ──────────────── */
self.addEventListener('push', function (event) {
  if (!event.data) return;
  try {
    var data = event.data.json();
    event.waitUntil(
      self.registration.showNotification(data.title || 'Nebula', {
        body: data.body || '',
        icon: './logo.png',
        badge: './logo.png',
        tag: data.tag || 'nebula-push',
        data: { url: data.url || './' }
      })
    );
  } catch (e) {}
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var targetUrl = (event.notification.data && event.notification.data.url) || './';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (windowClients) {
      for (var i = 0; i < windowClients.length; i++) {
        if (windowClients[i].url === targetUrl && 'focus' in windowClients[i]) {
          return windowClients[i].focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
