// NotesAI Service Worker
// Handles offline fallback and static asset caching only.
// NEVER caches HTML, private data, JWT tokens, or authenticated API responses.

const CACHE_NAME = 'notesai-v2';
const OFFLINE_URL = '/offline';

// Static assets to cache (app shell only; HTML is intentionally excluded)
const PRECACHE_ASSETS = [
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  '/offline',
];

// Install: precache app shell
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('Precache failed for some assets:', err);
      });
    })
  );
  self.skipWaiting();
});

// Activate: clean old caches (removes notesai-v1 and its cached HTML)
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch: never cache HTML or private data; static assets only.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/') ||
      url.pathname.startsWith('/extract-text') || url.pathname.startsWith('/generate-pdf')) {
    return;
  }
  if (event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).catch(() => caches.match(OFFLINE_URL)));
    return;
  }
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request).then((response) => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      }))
    );
  }
});
