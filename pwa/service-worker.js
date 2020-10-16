'use strict';

const CACHE_NAME = 'pwapwdb';

const FILES_TO_CACHE = [
  './index.html',
  './manifest.json',
  './icons/lock-256x256.png',
  './icons/lock-512x512.png',
  './service-worker.js',
  './static/wasm.d.ts',
  './static/wasm.js',
  './static/wasm_bg.d.ts',
  './static/wasm_bg.wasm'
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
    caches.keys().then((keyList) => {
      return Promise.all(keyList.map((key) => {
        if (key !== CACHE_NAME) {
          return caches.delete(key);
        }
      }));
    })
  );

  self.clients.claim();
});

self.addEventListener('fetch', (evt) => {
  if (evt.request.mode !== 'navigate') {
    // Not a page navigation, bail.
    return;
  }
  evt.respondWith(
    fetch(evt.request).catch(() => {
      return caches.open(CACHE_NAME).then((cache) => {
        return cache.match('./index.html');
      });
    })
  );
});