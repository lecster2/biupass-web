/* BiuPass 网页版（只读）
 * 和电脑版用完全相同的加密格式：Argon2id(恢复密钥) → 解开保险库钥匙 → AES-256-GCM 解密内容。
 * 页面没有联网权限（CSP connect-src 'none'），所有数据只在这台设备的浏览器里。 */
'use strict';

const RECOVERY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEAM_CHARS = '23456789BCDFGHJKMNPQRTVWXY';
const IDLE_LOCK_MS = 5 * 60 * 1000;
const HIDDEN_LOCK_MS = 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const TYPES = {
  generated: ['🎲', '生成记录'], password: ['🔑', '账号密码'], codes: ['🧾', '安全码/备用码'],
  totp: ['⏱', '验证器'], note: ['📝', '安全笔记'], card: ['💳', '银行卡'], unknown: ['❔', '新版本的类型'],
};
const KNOWN = new Set(['password', 'codes', 'totp', 'note', 'card']);

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
const aad = (name) => enc.encode('biupass:v1:' + name);
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (u8) => btoa(String.fromCharCode(...u8));

// ------------------------------------------------------------ 状态（锁定时全部清掉）
let fileBytes = null;      // 加密的保险库文件（vault.json 或 zip）
let fileName = '';
let header = null;         // vault.json 的明文头部（本身不含任何秘密）
let blobs = null;          // zip 里的加密附件 {文件名: Uint8Array}
let vaultKey = null;       // 解锁后才有：32 字节
let entries = [];
let filter = 'all';
let current = null;        // 正在查看的记录
let timers = [];
let lastActive = Date.now();
let hiddenAt = 0;

// ------------------------------------------------------------ 小工具

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add('hidden'), 2200);
}

function show(view) {
  for (const v of ['view-unlock', 'view-list', 'view-detail', 'view-settings']) $(v).classList.toggle('hidden', v !== view);
  const unlocked = vaultKey !== null;
  $('btn-lock').classList.toggle('hidden', !unlocked);
  $('btn-settings').classList.toggle('hidden', !unlocked);
  window.scrollTo(0, 0);
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function setMsg(id, text, kind = 'err') {
  const m = $(id);
  m.textContent = text;
  m.className = 'msg ' + kind;
}

// ------------------------------------------------------------ 加密

async function aesDecrypt(keyBytes, nonce, ct, ad) {
  const k = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, k, ct));
}

async function aesEncrypt(keyBytes, plain, ad) {
  const k = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, k, plain));
  return { nonce, ct };
}

async function hkdf(ikm, info) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) }, k, 256);
  return new Uint8Array(bits);
}

function normalizeRecovery(text) {
  let s = (text || '').normalize('NFKC').toUpperCase().replace(/[^0-9A-Z]/g, '');
  s = s.replace(/0/g, 'O').replace(/1/g, 'I').replace(/8/g, 'B');
  if (s.length !== 32 || [...s].some((ch) => !RECOVERY_ALPHABET.includes(ch))) return null;
  return enc.encode(s);
}

async function argon2(secret, salt, kdf) {
  if (kdf.type !== 'argon2id') throw new Error('不支持的密钥算法');
  return hashwasm.argon2id({
    password: secret, salt, parallelism: kdf.lanes, iterations: kdf.iterations,
    memorySize: kdf.memory_kib, hashLength: 32, outputType: 'binary',
  });
}

// ------------------------------------------------------------ 读文件（vault.json 或 不压缩的 zip）

function readZip(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let eocd = -1;
  for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('bad_zip');
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const files = {};
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) throw new Error('bad_zip');
    const method = dv.getUint16(p + 10, true);
    const size = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const local = dv.getUint32(p + 42, true);
    const name = dec.decode(u8.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;
    if (method !== 0) throw new Error('compressed_zip');
    if (dv.getUint32(local, true) !== 0x04034b50) throw new Error('bad_zip');
    const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
    files[name] = u8.subarray(start, start + size);
  }
  return files;
}

function loadFile(bytes, name) {
  let h;
  let atts = {};
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    const files = readZip(bytes);
    if (!files['vault.json']) throw new Error('这个 zip 里没有 vault.json');
    h = JSON.parse(dec.decode(files['vault.json']));
    for (const [n, data] of Object.entries(files)) {
      const m = /^attachments\/([0-9a-f]{32})\.bin$/.exec(n);
      if (m) atts[m[1]] = data;
    }
  } else {
    h = JSON.parse(dec.decode(bytes));
  }
  if (!h || h.app !== 'BiuPass' || typeof h.format !== 'number') throw new Error('不是 BiuPass 保险库文件');
  if (h.format > 1) throw new Error('这个保险库来自更新版本的软件，网页版需要更新后才能打开');
  if (!h.slots || !h.slots.recovery) throw new Error('这个保险库没有恢复密钥槽');
  fileBytes = bytes; fileName = name; header = h; blobs = atts;
}

function describeFile() {
  const box = $('file-info');
  if (!header) { box.classList.add('hidden'); return; }
  const n = Object.keys(blobs).length;
  box.textContent = `✅ ${fileName}  ·  最后由 v${header.written_by || '?'} 保存于 ${fmtTime(header.updated)}`
    + (n ? `  ·  ${n} 个附件` : '');
  box.classList.remove('hidden');
}

// ------------------------------------------------------------ 本机存储（IndexedDB）：加密文件 + 快速解锁

function db() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open('biupass-web', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function kv(op, key, value) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const tx = d.transaction('kv', op === 'get' ? 'readonly' : 'readwrite');
    const s = tx.objectStore('kv');
    const r = op === 'get' ? s.get(key) : op === 'put' ? s.put(value, key) : s.delete(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

// ------------------------------------------------------------ 解锁 / 锁定

async function openPayload(key) {
  const d = header.data;
  const plain = await aesDecrypt(key, b64d(d.nonce), b64d(d.ct), aad('data'));
  const payload = JSON.parse(dec.decode(plain));
  vaultKey = key;
  entries = (payload.entries || []).filter((e) => !e.deleted_at);  // 「最近删除」里的不显示
  plain.fill(0);
  lastActive = Date.now();
  filter = 'all';
  $('search').value = '';
  renderChips();
  renderList();
  show('view-list');
  if ($('remember-file').checked && fileBytes) {
    await kv('put', 'file', { bytes: fileBytes, name: fileName, saved: Date.now() });
  }
}

async function unlockWithRecovery() {
  if (!header) { setMsg('unlock-msg', '请先选择保险库文件'); return; }
  const secret = normalizeRecovery($('recovery').value);
  if (!secret) { setMsg('unlock-msg', '恢复密钥格式不对：应为 8 组、每组 4 个字符'); return; }
  const btn = $('btn-unlock');
  btn.disabled = true;
  setMsg('unlock-msg', '正在验证…（为了防暴力破解，这一步故意算得慢，手机上约 5–20 秒）', 'muted');
  try {
    const slot = header.slots.recovery;
    const kek = await argon2(secret, b64d(slot.salt), header.kdf);
    let key;
    try {
      key = await aesDecrypt(kek, b64d(slot.nonce), b64d(slot.ct), aad('slot:recovery'));
    } catch (e) {
      setMsg('unlock-msg', '恢复密钥错误');
      return;
    }
    $('recovery').value = '';
    setMsg('unlock-msg', '');
    await openPayload(key);
  } catch (e) {
    setMsg('unlock-msg', '解锁失败：' + (e.message || e));
  } finally {
    btn.disabled = false;
  }
}

function lock(reason) {
  if (vaultKey) vaultKey.fill(0);
  vaultKey = null;
  entries = [];
  current = null;
  for (const t of timers) clearInterval(t);
  timers = [];
  $('list').replaceChildren();
  $('detail').replaceChildren();
  show('view-unlock');
  refreshPasskeyBox();
  if (reason) setMsg('unlock-msg', reason, 'muted');
}

function touch() { lastActive = Date.now(); }

setInterval(() => {
  if (vaultKey && Date.now() - lastActive > IDLE_LOCK_MS) lock('5 分钟没有操作，已自动锁定');
}, 5000);

document.addEventListener('visibilitychange', () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (vaultKey && hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS) lock('离开超过 1 分钟，已自动锁定');
});
for (const ev of ['pointerdown', 'keydown', 'scroll']) document.addEventListener(ev, touch, { passive: true });

// ------------------------------------------------------------ Passkey 快速解锁（WebAuthn PRF）

const passkeySupported = () => !!(window.PublicKeyCredential && navigator.credentials);

async function prfFromAssertion(credId, salt) {
  const a = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const r = a.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) throw new Error('no_prf');
  return new Uint8Array(r.results.first);
}

async function enrollPasskey() {
  setMsg('enroll-msg', '');
  if (!passkeySupported()) { setMsg('enroll-msg', '这个浏览器不支持 passkey'); return; }
  try {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'BiuPass 网页版' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'BiuPass', displayName: 'BiuPass 网页版' },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    const ext = cred.getClientExtensionResults().prf;
    if (!ext || ext.enabled === false) { setMsg('enroll-msg', '这台设备的 passkey 不支持加密（PRF），没法用于快速解锁'); return; }
    const credId = new Uint8Array(cred.rawId);
    const out = ext.results && ext.results.first ? new Uint8Array(ext.results.first) : await prfFromAssertion(credId, salt);
    const wrapKey = await hkdf(out, 'biupass-web-passkey-v1');
    const { nonce, ct } = await aesEncrypt(wrapKey, vaultKey, aad('web:passkey'));
    await kv('put', 'passkey', { credId, salt, nonce, ct, vaultId: header.vault_id || '', created: Date.now() });
    setMsg('enroll-msg', '✅ 已登记。下次打开网页直接点「用 Face ID / 指纹解锁」。', 'ok');
    refreshSettings();
  } catch (e) {
    setMsg('enroll-msg', e.name === 'NotAllowedError' ? '已取消' : '登记失败：' + (e.message || e));
  }
}

async function unlockWithPasskey() {
  setMsg('unlock-msg', '');
  try {
    const pk = await kv('get', 'passkey');
    if (!pk || !header) return;
    const out = await prfFromAssertion(pk.credId, pk.salt);
    const wrapKey = await hkdf(out, 'biupass-web-passkey-v1');
    let key;
    try {
      key = await aesDecrypt(wrapKey, pk.nonce, pk.ct, aad('web:passkey'));
    } catch (e) {
      setMsg('unlock-msg', 'Face ID 验证通过了，但解不开（可能换过 passkey）。请用恢复密钥解锁后重新登记。');
      return;
    }
    await openPayload(key);
  } catch (e) {
    if (e.message === 'BAD_VAULT') return;
    setMsg('unlock-msg', e.name === 'NotAllowedError' ? '已取消，也可以输入恢复密钥' : '快速解锁失败：' + (e.message || e)
      + '\n如果电脑上换过保险库（不是同一份了），请用恢复密钥解锁。');
  }
}

async function refreshPasskeyBox() {
  const pk = await kv('get', 'passkey').catch(() => null);
  $('passkey-box').classList.toggle('hidden', !(pk && header && (!pk.vaultId || pk.vaultId === (header.vault_id || ''))));
}

async function refreshSettings() {
  const pk = await kv('get', 'passkey').catch(() => null);
  $('passkey-state').textContent = pk ? `✅ 已登记（${new Date(pk.created).toLocaleString()}）` : '还没有登记';
  $('btn-enroll').textContent = pk ? '重新登记' : '登记 Face ID / 指纹';
  $('btn-unenroll').classList.toggle('hidden', !pk);
  const f = await kv('get', 'file').catch(() => null);
  $('stored-info').textContent = f ? `${f.name}（${(f.bytes.length / 1024).toFixed(0)} KB，${new Date(f.saved).toLocaleString()} 记住的）`
    : '没有记住文件';
}

// ------------------------------------------------------------ 列表

function kindOf(e) {
  if (!KNOWN.has(e.type)) return 'unknown';
  if (e.type === 'password' && e.source === 'generator') return 'generated';
  return e.type;
}

function titleOf(e) {
  if (e.title) return e.title;
  if (e.type === 'card' && e.number) return '银行卡 ' + maskCard(e.number);
  if (e.note) return e.note.split('\n')[0];
  return '（未备注）';
}

function subtitleOf(e) {
  const k = kindOf(e);
  if (k === 'codes') {
    const c = e.codes || [];
    return `${c.filter((x) => !x.used).length} / ${c.length} 个可用`;
  }
  if (k === 'card') return [e.bank, e.holder].filter(Boolean).join(' · ');
  if (k === 'totp') return (e.totp && e.totp.kind === 'steam' ? 'Steam 令牌' : '动态验证码') + (e.username ? ' · ' + e.username : '');
  return e.username || e.url || '';
}

const cleanCard = (n) => (n || '').replace(/\D/g, '');
const maskCard = (n) => '•••• ' + cleanCard(n).slice(-4);
const groupCard = (n) => cleanCard(n).replace(/(.{4})(?=.)/g, '$1 ');

function renderChips() {
  const counts = {};
  for (const e of entries) counts[kindOf(e)] = (counts[kindOf(e)] || 0) + 1;
  const box = $('chips');
  box.replaceChildren();
  for (const k of ['all', 'password', 'codes', 'totp', 'note', 'card', 'generated']) {
    if (k !== 'all' && !counts[k]) continue;
    const label = k === 'all' ? `全部 ${entries.length}` : `${TYPES[k][0]} ${TYPES[k][1]} ${counts[k]}`;
    box.append(el('button', { class: k === filter ? 'on' : '', text: label, onclick: () => { filter = k; renderChips(); renderList(); } }));
  }
}

function renderList() {
  const q = $('search').value.trim().toLowerCase();
  const list = $('list');
  list.replaceChildren();
  const shown = entries.filter((e) => {
    if (filter !== 'all' && kindOf(e) !== filter) return false;
    if (!q) return true;
    const hay = ['title', 'username', 'url', 'note', 'content', 'bank', 'holder'].map((k) => e[k] || '').join(' ')
      + ' ' + cleanCard(e.number).slice(-4);
    return hay.toLowerCase().includes(q);
  }).sort((a, b) => (b.created || 0) - (a.created || 0));
  for (const e of shown) {
    const k = kindOf(e);
    list.append(el('li', { onclick: () => openDetail(e) },
      el('div', { class: 'icon', text: TYPES[k][0] }),
      el('div', { class: 'main' }, el('div', { class: 't', text: titleOf(e) }), el('div', { class: 's', text: subtitleOf(e) }))));
  }
  $('list-count').textContent = `共 ${shown.length} 条`;
}

// ------------------------------------------------------------ 详情

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`已复制${what}（30 秒后尝试清空剪贴板）`);
    clearTimeout(copy.timer);
    copy.timer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIPBOARD_CLEAR_MS);
  } catch (e) {
    toast('复制失败，请长按手动复制');
  }
}

function field(box, label, value, { secret = false, mono = false, display = null } = {}) {
  if (value == null || value === '') return;
  const shownText = display || value;
  const v = el('div', { class: 'v' + (mono ? ' mono' : '') + (secret ? ' secret' : ''), text: secret ? '••••••••' : shownText });
  const row = el('div', { class: 'row' }, v);
  if (secret) {
    let open = false;
    row.append(el('button', { text: '👁', onclick: () => { open = !open; v.textContent = open ? shownText : '••••••••'; v.classList.toggle('secret', !open); } }));
  }
  row.append(el('button', { text: '复制', onclick: () => copy(value, label) }));
  box.append(el('div', { class: 'field' }, el('div', { class: 'k', text: label }), row));
}

function openDetail(e) {
  current = e;
  for (const t of timers) clearInterval(t);
  timers = [];
  const box = $('detail');
  box.replaceChildren();
  const k = kindOf(e);
  box.append(el('div', { class: 'kind', text: TYPES[k].join(' ') }), el('div', { class: 'title', text: titleOf(e) }));
  if (k === 'unknown') {
    box.append(el('p', { class: 'muted', text: '这条记录来自更新版本的软件，网页版还不能显示它的内容。' }));
  }
  if (e.type === 'password') {
    field(box, '账号', e.username);
    field(box, '密码', e.password, { secret: true, mono: true });
    field(box, '网址', e.url);
  } else if (e.type === 'codes') {
    renderCodes(box, e.codes || []);
  } else if (e.type === 'totp') {
    renderTotp(box, e.totp || {});
    field(box, '账号', e.username);
    field(box, '恢复码（如 Steam 的 R 码）', e.recovery, { secret: true, mono: true });
  } else if (e.type === 'note') {
    field(box, '内容', e.content);
  } else if (e.type === 'card') {
    field(box, '发卡行', e.bank);
    field(box, '持卡人', e.holder);
    field(box, '卡号', cleanCard(e.number), { secret: true, mono: true, display: groupCard(e.number) });
    field(box, '有效期', e.expiry, { mono: true });
    field(box, 'CVV', e.cvv, { secret: true, mono: true });
    field(box, '银行卡密码', e.pin, { secret: true, mono: true });
  }
  field(box, '备注', e.note);
  renderAttachments(box, e.attachments || []);
  box.append(el('p', { class: 'muted small', text: `创建 ${fmtTime(e.created)}　修改 ${fmtTime(e.updated)}` }));
  show('view-detail');
}

function renderCodes(box, codes) {
  const free = codes.filter((c) => !c.used).length;
  const wrap = el('div', { class: 'field' }, el('div', { class: 'k', text: `安全码（还剩 ${free} / ${codes.length} 个没用过）` }));
  const ul = el('ul', { class: 'codes' });
  codes.forEach((c, i) => {
    const used = c.used ? el('span', { class: 'u', text: '已用' + (c.used_at ? ' ' + c.used_at.replace('T', ' ').slice(0, 16) : '') }) : null;
    ul.append(el('li', { class: c.used ? 'used' : '' }, el('span', { class: 'n', text: String(i + 1) }),
      el('span', { class: 'c', text: c.code }), used,
      c.used ? null : el('button', { text: '复制', onclick: () => copy(c.code, '安全码') })));
  });
  wrap.append(ul, el('p', { class: 'muted small', text: '网页版是只读的：用掉一个码后，请在电脑上勾选「已用」。' }));
  box.append(wrap);
}

// ---- TOTP / Steam 令牌（和电脑版 totp.py 一致）

function base32(s) {
  const clean = s.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '');
  const out = [];
  let bits = 0, val = 0;
  for (const ch of clean) {
    const i = RECOVERY_ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('bad_secret');
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

function decodeSecret(cfg) {
  const s = (cfg.secret || '').trim();
  if (cfg.kind === 'steam' && s.length === 28 && s.endsWith('=')) return b64d(s);
  return base32(s);
}

async function totpNow(cfg, now = Date.now() / 1000) {
  const period = Number(cfg.period) || 30;
  const algo = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[(cfg.kind === 'steam' ? 'SHA1' : cfg.algorithm || 'SHA1').toUpperCase()] || 'SHA-1';
  const key = await crypto.subtle.importKey('raw', decodeSecret(cfg), { name: 'HMAC', hash: algo }, false, ['sign']);
  const counter = new Uint8Array(8);
  let c = Math.floor(now / period);
  for (let i = 7; i >= 0; i--) { counter[i] = c & 0xff; c = Math.floor(c / 256); }
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const o = h[h.length - 1] & 0x0f;
  let full = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  let code;
  if (cfg.kind === 'steam') {
    code = '';
    for (let i = 0; i < 5; i++) { code += STEAM_CHARS[full % STEAM_CHARS.length]; full = Math.floor(full / STEAM_CHARS.length); }
  } else {
    const digits = Number(cfg.digits) || 6;
    code = String(full % 10 ** digits).padStart(digits, '0');
  }
  return [code, period - Math.floor(now % period)];
}

function renderTotp(box, cfg) {
  const code = el('div', { class: 'otp', text: '······' });
  const ring = el('span', { class: 'ring' });
  let value = '';
  const row = el('div', { class: 'row' }, el('div', { class: 'v' }, code, ring),
    el('button', { text: '复制', onclick: () => copy(value, '验证码') }));
  box.append(el('div', { class: 'field' }, el('div', { class: 'k', text: cfg.kind === 'steam' ? 'Steam 令牌验证码' : '动态验证码' }), row));
  const tick = async () => {
    try {
      const [c, left] = await totpNow(cfg);
      value = c;
      code.textContent = cfg.kind === 'steam' ? c : c.replace(/(\d{3})(?=\d)/, '$1 ');
      ring.textContent = `　${left} 秒后更新`;
    } catch (e) {
      code.textContent = '密钥无法识别';
    }
  };
  tick();
  timers.push(setInterval(tick, 1000));
}

// ---- 附件（在本机解密；图片直接显示，其他文件生成本地下载链接，不经过网络）

function renderAttachments(box, atts) {
  if (!atts.length) return;
  const wrap = el('div', { class: 'field' }, el('div', { class: 'k', text: `📎 附件（${atts.length}）` }));
  for (const a of atts) {
    const item = el('div', { class: 'att' });
    const blob = blobs[a.id];
    if (!blob) {
      item.append(el('div', { class: 'muted small', text: `${a.name}：这个文件里没有附件内容（请导出带附件的 .zip 备份）` }));
    } else {
      const btn = el('button', { text: (a.mime || '').startsWith('image/') ? `🖼 查看 ${a.name}` : `📄 打开 ${a.name}` });
      btn.addEventListener('click', async () => {
        try {
          const plain = await aesDecrypt(vaultKey, blob.subarray(0, 12), blob.subarray(12), aad('att:' + a.id));
          const url = URL.createObjectURL(new Blob([plain], { type: a.mime || 'application/octet-stream' }));
          setTimeout(() => URL.revokeObjectURL(url), 60000);
          if ((a.mime || '').startsWith('image/')) item.replaceChildren(el('img', { src: url, alt: a.name }));
          else item.replaceChildren(el('a', { href: url, download: a.name, text: `⬇ 保存 ${a.name}` }));
        } catch (e) {
          toast('附件解密失败（文件可能损坏）');
        }
      });
      item.append(btn);
    }
    wrap.append(item);
  }
  box.append(wrap);
}

// ------------------------------------------------------------ 绑定事件、启动

$('file-input').addEventListener('change', async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  try {
    loadFile(new Uint8Array(await f.arrayBuffer()), f.name);
    describeFile();
    setMsg('unlock-msg', '');
    refreshPasskeyBox();
    $('recovery').focus();
  } catch (e) {
    setMsg('unlock-msg', e.message === 'compressed_zip' ? '这个 zip 被压缩过了，请直接用软件导出的 zip（不要再用压缩软件打包）'
      : '读取失败：' + (e.message === 'bad_zip' ? '不是有效的 zip' : e.message));
  }
  ev.target.value = '';
});
$('btn-unlock').addEventListener('click', unlockWithRecovery);
$('recovery').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') unlockWithRecovery(); });
$('btn-passkey').addEventListener('click', unlockWithPasskey);
$('btn-lock').addEventListener('click', () => lock('已锁定'));
$('search').addEventListener('input', renderList);
$('btn-back').addEventListener('click', () => { for (const t of timers) clearInterval(t); timers = []; show('view-list'); });
$('btn-settings').addEventListener('click', () => { refreshSettings(); show('view-settings'); });
$('btn-settings-back').addEventListener('click', () => show('view-list'));
$('btn-enroll').addEventListener('click', enrollPasskey);
$('btn-unenroll').addEventListener('click', async () => { await kv('del', 'passkey'); refreshSettings(); toast('已取消快速解锁'); });
$('btn-forget').addEventListener('click', async () => {
  await kv('del', 'file'); await kv('del', 'passkey');
  refreshSettings(); toast('已删除');
});

// ------------------------------------------------------------ 版本与更新：装好后不自动更新，有新版本只提示

const WEB_VERSION = '6.0';
const newer = (a, b) => {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return false;
};

function askWorker(type) {
  const sw = navigator.serviceWorker && navigator.serviceWorker.controller;
  if (sw) sw.postMessage({ type });
  return !!sw;
}

function onWorkerMessage(ev) {
  const m = ev.data || {};
  if (m.type === 'version') {
    if (m.error) { setMsg('update-msg', '现在连不上网，检查不了更新（不影响使用）', 'muted'); return; }
    if (m.latest && newer(m.latest, WEB_VERSION)) {
      $('update-text').textContent = `有新版本 v${m.latest} 可以更新${m.notes ? '：' + m.notes : ''}`;
      $('update-bar').classList.remove('hidden');
      setMsg('update-msg', `有新版本 v${m.latest}`, 'ok');
    } else {
      setMsg('update-msg', '已经是最新版本', 'ok');
    }
  } else if (m.type === 'updated') {
    toast('已更新，正在重新打开…');
    setTimeout(() => location.reload(), 600);
  } else if (m.type === 'update-failed') {
    $('btn-update').disabled = false;
    setMsg('update-msg', '更新失败（网络问题），还在用原来的版本：' + m.error);
    toast('更新失败，还在用原来的版本');
  }
}

$('web-version').textContent = 'v' + WEB_VERSION;
$('btn-check-update').addEventListener('click', () => {
  if (!askWorker('check')) setMsg('update-msg', '本机测试模式（没有离线缓存），不检查更新', 'muted');
});
$('btn-update').addEventListener('click', () => {
  $('btn-update').disabled = true;
  $('update-text').textContent = '正在下载新版本…';
  if (vaultKey) lock('更新前已锁定');
  askWorker('update');
});
$('btn-update-later').addEventListener('click', () => $('update-bar').classList.add('hidden'));

(async function start() {
  try {
    const f = await kv('get', 'file');
    if (f) { loadFile(f.bytes, f.name); describeFile(); }
  } catch (e) { /* 没有记住的文件 */ }
  refreshPasskeyBox();
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.addEventListener('message', onWorkerMessage);
    navigator.serviceWorker.register('sw.js', { updateViaCache: 'all' }).catch(() => {});
    navigator.serviceWorker.ready.then(() => setTimeout(() => askWorker('check'), 1500));
  }
})();

// 测试用（只在本机测试页面里用到）
window.__biupass = { normalizeRecovery, totpNow, readZip, loadFile };
