var CACHE = 'belezapro-v1';
var ASSETS = [
  '/painel.html',
  '/agendar.html'
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(c) {
      return c.addAll(ASSETS);
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE; })
            .map(function(k) { return caches.delete(k); })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', function(e) {
  // Só intercepta GET do mesmo domínio
  if (e.request.method !== 'GET') return;
  if (!e.request.url.startsWith(self.location.origin)) return;

  // Estratégia: Network First para a API, Cache First para assets estáticos
  var url = new URL(e.request.url);
  
  if (url.hostname.includes('railway.app')) {
    // API: sempre vai para a rede, sem cache
    return;
  }

  e.respondWith(
    fetch(e.request)
      .then(function(response) {
        // Atualiza cache com resposta fresca
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE).then(function(c) { c.put(e.request, clone); });
        }
        return response;
      })
      .catch(function() {
        // Offline: serve do cache
        return caches.match(e.request);
      })
  );
});
