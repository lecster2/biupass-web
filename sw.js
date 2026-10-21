// 离线缓存 + 「不自动更新」：装好后一直用手机里存的那一份网页。
// 只有在页面上点「更新」时，才去网上取新版本（version.json 里列出的文件）整份换掉。
// 这个文件尽量永远不改：浏览器发现 sw.js 变了会自动装新的，那就绕过了「不自动更新」。
const CACHE = 'biupass-web';

async function fetchVersion() {
  const r = await fetch('version.json', { cache: 'no-store' });
  if (!r.ok) throw new Error('version.json ' + r.status);
  return r.json();
}

async function installVersion(info) {
  // 先全部下载到临时缓存，全部成功才替换（中途断网不会留下一半新一半旧）
  const tmp = await caches.open(CACHE + '-new');
  const files = ['./', ...info.files];
  for (const f of files) {
    const r = await fetch(f, { cache: 'reload' });
    if (!r.ok) throw new Error(f + ' ' + r.status);
    await tmp.put(f, r);
  }
  await tmp.put('version.json', new Response(JSON.stringify(info), { headers: { 'Content-Type': 'application/json' } }));
  await caches.delete(CACHE);
  const cur = await caches.open(CACHE);
  for (const req of await tmp.keys()) await cur.put(req, await tmp.match(req));
  await caches.delete(CACHE + '-new');
}

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const have = await caches.open(CACHE).then((c) => c.match('version.json'));
    if (!have) await installVersion(await fetchVersion());  // 第一次打开：存一份
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// 永远先用存好的那一份；存的里面没有的（不应该发生）才上网取
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(caches.open(CACHE).then((c) => c.match(e.request, { ignoreSearch: true }))
    .then((hit) => hit || fetch(e.request)));
});

// 页面发来的指令：check = 看看网上有没有新版本；update = 用户点了「更新」
self.addEventListener('message', (e) => {
  const reply = (msg) => e.source && e.source.postMessage(msg);
  if (!e.data) return;
  if (e.data.type === 'check') {
    Promise.all([fetchVersion(), caches.open(CACHE).then((c) => c.match('version.json')).then((r) => r && r.json())])
      .then(([latest, current]) => reply({ type: 'version', latest: latest.version, current: current && current.version,
        notes: latest.notes || '' }))
      .catch(() => reply({ type: 'version', error: true }));
  } else if (e.data.type === 'update') {
    fetchVersion().then(installVersion).then(() => reply({ type: 'updated' }))
      .catch((err) => reply({ type: 'update-failed', error: String(err) }));
  }
});
