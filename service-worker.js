'use strict';

const CACHE_NAME = 'pwapwdb';

const FILES_TO_CACHE = [
  './index.html',
  './manifest.json',
  './icons/lock-256x256.png',
  './icons/lock-512x512.png',
  './service-worker.js',
  './wasm/wasm.d.ts',
  './wasm/wasm.js',
  './wasm/wasm_bg.d.ts',
  './wasm/wasm_bg.wasm'
];


self.addEventListener('install', (evt) => {
  evt.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(FILES_TO_CACHE);
    })
  );

  self.skipWaiting();
});

self.addEventListener('activate', (evt) => {
  evt.waitUntil(
    (async () => {
      // Enable navigation preload if it's supported.
      // See https://developers.google.com/web/updates/2017/02/navigation-preload
      if ("navigationPreload" in self.registration) {
        await self.registration.navigationPreload.enable();
      }
    })()
  );

  self.clients.claim();
});

self.addEventListener('fetch', (evt) => {
  if (evt.request.mode !== 'navigate') {
    // Not a page navigation, bail.
    return;
  }
  evt.respondWith(
    (async () => {
      try {
        // First, try to use the navigation preload response if it's supported.
        const preloadResponse = await evt.preloadResponse;
        if (preloadResponse) {
          return preloadResponse;
        }

        // Always try the network first.
        const networkResponse = await fetch(evt.request);
        return networkResponse;
      } catch (error) {
        // catch is only triggered if an exception is thrown, which is likely
        // due to a network error.
        // If fetch() returns a valid HTTP response with a response code in
        // the 4xx or 5xx range, the catch() will NOT be called.
        console.log("Fetch failed; returning offline page instead.", error);

        const cache = await caches.open(CACHE_NAME);
//        const cachedResponse = await cache.match('./index.html');
        const cachedResponse = await cache.match(evt.request);
        return cachedResponse;
      }
    })()
  );
});