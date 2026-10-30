// 聪明搜索（网页版，v8.6）：和软件里的 biupass/smartsearch.py 同一套规则（数据在 search-data.js，从 Python 生成）。
// 搜索框里的话按空格分成几个条件，每个都要对上；一个条件可以直接包含、同义词 / 大类 / 中英文品牌名、记录类型和状态、
// 拼音首字母（zfb → 支付宝）、打错一两个字母（gihub → GitHub）。按「对得有多准」排序。
// 绝不搜索：密码、卡密 / 备用码本身、卡号（只认后四位）、CVV、标了保密的自定义字段。
// 卡密的条件（欧区、€20、20欧、steam、充值卡）和软件里一样解析（giftcodes.py 的正则原样搬过来）。
'use strict';

const SS = (() => {
  const D = SEARCH_DATA;
  const W = D.weights;
  const initialOf = new Map();
  for (const [letter, chars] of Object.entries(D.initials)) for (const ch of chars) initialOf.set(ch, letter);
  for (const [ch, opts] of Object.entries(D.special)) initialOf.set(ch, opts);
  const G = D.gift;
  const reEscape = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rePrefix = new RegExp(G.prefixAmount, 'g');
  const reSuffix = new RegExp(G.suffixAmount, 'gi');
  const reValueWord = new RegExp(G.valueWord, 'i');
  const reBare = new RegExp(G.bareNumber);
  const reWallet = new RegExp(G.walletWords, 'i');
  const reGame = new RegExp(G.gameWords, 'i');
  const suffixMap = new Map(Object.entries(G.suffixMap));
  const regionEn = Object.entries(G.regionWords).map(([rid, r]) => [rid,
    r.en.map((w) => new RegExp('(?<![a-z])' + reEscape(w) + '(?![a-z])')),
    r.codes.map((c) => new RegExp('(?<![A-Za-z0-9])' + c + '(?![A-Za-z0-9])'))]);
  const byPos = (a, b) => (a[0] - b[0]) || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) ||
    (String(a[2]) < String(b[2]) ? -1 : String(a[2]) > String(b[2]) ? 1 : 0);  // 和 Python 的 min(元组) 一样

  function amount(num) {  // giftcodes._amount
    num = num.replace(/,/g, '.');
    if (num.includes('.')) num = num.replace(/0+$/, '').replace(/\.$/, '');
    return num.replace(/^0+/, '') || '0';
  }

  function findRegion(text) {
    const hits = [];
    const low = text.toLowerCase();
    for (const [rid, en, codes] of regionEn) {
      for (const w of G.regionWords[rid].zh) { const i = text.indexOf(w); if (i >= 0) hits.push([i, rid]); }
      for (const re of en) { const m = re.exec(low); if (m) hits.push([m.index, rid]); }
      for (const re of codes) { const m = re.exec(text); if (m) hits.push([m.index, rid]); }
    }
    return hits.length ? hits.sort(byPos)[0][1] : '';
  }

  function findPlatform(text) {
    const low = text.toLowerCase();
    const hits = [];
    for (const [pid, words] of Object.entries(G.platformWords)) {
      for (const w of words) { const i = low.indexOf(w); if (i >= 0) hits.push([i, pid]); }
    }
    return hits.length ? hits.sort(byPos)[0][1] : '';
  }

  function findKind(text) {
    const w = reWallet.exec(text), g = reGame.exec(text);
    if (w && (!g || w.index <= g.index)) return 'wallet';
    return g ? 'game' : '';
  }

  function findValue(text, region) {
    const hits = [];
    for (const m of text.matchAll(rePrefix)) hits.push([m.index, G.prefixMap[m[1]], m[2]]);
    for (const m of text.matchAll(reSuffix)) hits.push([m.index, suffixMap.get(m[2].toUpperCase()), m[1]]);
    const cur0 = region ? G.regionWords[region].currency : '';
    if (hits.length) {
      let [, cur, num] = hits.sort(byPos)[0];
      if (cur === 'CNY' && region === 'JP') cur = 'JPY';
      if (cur === 'USD' && G.dollarRegions.includes(region)) cur = cur0;
      return [cur, amount(num)];
    }
    const m = reValueWord.exec(text);
    if (m) return [cur0, amount(m[1])];
    if (region) {
      const b = reBare.exec(text);
      if (b && parseFloat(b[1].replace(',', '.')) > 0 && parseFloat(b[1].replace(',', '.')) <= 100000 && !/^(19|20)\d\d$/.test(b[1])) {
        return [cur0, amount(b[1])];
      }
    }
    return ['', ''];
  }

  function giftMatch(term, e) {  // smartsearch._gift_match
    const g = e.gift || {};
    if (!Object.keys(g).length || !(term.region || term.value || term.platform || term.giftKind)) return false;
    if (term.region && g.region !== term.region) return false;
    if (term.value && amount(String(g.value || '')) !== term.value) return false;
    if (term.currency && g.currency && g.currency !== term.currency) return false;
    if (term.platform && g.platform !== term.platform) return false;
    if (term.giftKind && g.kind !== term.giftKind) return false;
    return true;
  }

  const typeLookup = new Map();
  for (const [kind, words] of Object.entries(D.typeWords)) for (const w of words) typeLookup.set(w, kind);

  function initials(text, limit = 8) {
    let variants = [''];
    for (const ch of String(text || '').toLowerCase()) {
      if (ch.charCodeAt(0) < 128) {
        const add = /[a-z0-9]/.test(ch) ? ch : ' ';
        variants = variants.map((v) => v + add);
        continue;
      }
      const opts = initialOf.get(ch);
      if (!opts) { variants = variants.map((v) => v + ' '); continue; }
      const next = [];
      for (const v of variants) for (const o of opts) next.push(v + o);
      variants = next.slice(0, limit);
    }
    return variants.map((v) => v.replace(/\s+/g, ' ').trim());
  }

  function damerauAtMost(a, b, k) {
    if (Math.abs(a.length - b.length) > k) return false;
    let prev2 = null;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i].concat(new Array(b.length).fill(0));
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        if (prev2 && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) cur[j] = Math.min(cur[j], prev2[j - 2] + 1);
      }
      if (Math.min(...cur) > k) return false;
      prev2 = prev; prev = cur;
    }
    return prev[prev.length - 1] <= k;
  }

  function giftText(g) {
    const parts = [g.name || ''];
    parts.push(...(D.gift.platforms[g.platform] || []), ...(D.gift.kinds[g.kind] || []), ...(D.gift.regions[g.region] || []));
    const value = g.value || '';
    if (value) {
      const cur = g.currency || '';
      const sym = D.gift.symbols[cur] || '';
      parts.push(value, `${sym}${value}`, `${value}${sym}`, `${value}${cur}`, `${cur}${value}`, `${value} ${cur}`);
    }
    return parts.filter(Boolean).join(' ');
  }

  function fieldsOf(e) {
    const other = ['note', 'content', 'recovery', 'holder', 'bank', 'recovery_email', 'phone', 'expires'].map((k) => String(e[k] || ''));
    for (const [k, f] of Object.entries(e)) {  // 自定义字段：名字都算，只有不保密的值才算
      if (!k.startsWith('cf:') || !f || typeof f !== 'object') continue;
      other.push(f.name || '');
      if (!f.secret) other.push(String(f.value ?? ''));
    }
    if (e.type === 'card') other.push(String(e.number || '').replace(/\D/g, '').slice(-4));
    if (e.gift && Object.keys(e.gift).length) other.push(giftText(e.gift));
    return { title: String(e.title || '').toLowerCase(),
      main: (String(e.username || '') + ' ' + String(e.url || '')).toLowerCase(),
      tags: (e.tags || []).join(' ').toLowerCase(),
      other: other.join(' ').toLowerCase() };
  }

  function synonyms(low) {
    const out = [];
    const cat = D.aliases[low] || low;
    if (D.categories[cat]) out.push(...D.categories[cat]);
    for (const group of D.brands) if (group.includes(low)) out.push(...group.filter((w) => w !== low));
    return [...new Set(out.filter((w) => w !== low))];
  }

  function parse(query) {
    return String(query || '').trim().split(/[\s,，、;；]+/).filter(Boolean).slice(0, 8).map((raw) => {
      const low = raw.toLowerCase();
      const kind = typeLookup.get(low) || '';
      const region = kind ? '' : findRegion(raw);
      let [currency, value] = kind ? ['', ''] : findValue(raw, region);
      if (!value && /^\d{1,6}(?:[.,]\d{1,2})?$/.test(raw)) value = amount(raw);
      return { low, synonyms: synonyms(low), kind, region, currency, value,
        platform: kind ? '' : findPlatform(raw), giftKind: kind ? '' : findKind(raw),
        ascii: /^[a-z][a-z0-9.\-]*$/.test(low), pinyin: /^[a-z]{2,}$/.test(low) };
    });
  }

  function iso(d) { return d.toISOString().slice(0, 10); }

  function cardStatus(expiry, today) {  // 'expired' / 'soon'（60 天内）/ 'ok' / ''
    const t = String(expiry || '').trim();
    let m = t.match(/^(\d{4})[-/.](\d{1,2})$/);
    let month, year;
    if (m) { year = +m[1]; month = +m[2]; } else {
      m = t.match(/^(\d{1,2})\s*[-/.\s]?\s*(\d{2}|\d{4})$/);
      if (!m) return '';
      month = +m[1]; year = +m[2];
    }
    if (month < 1 || month > 12) return '';
    year = 2000 + (year % 100);
    const last = new Date(Date.UTC(year, month, 0));  // 那个月的最后一天
    const now = new Date(today + 'T00:00:00Z');
    if (now > last) return 'expired';
    return (last - now) / 86400000 <= 60 ? 'soon' : 'ok';
  }

  function kindMatch(kind, e, today) {
    const t = e.type;
    const hasGift = !!(e.gift && Object.keys(e.gift).length);
    switch (kind) {
      case 'gift': return hasGift;
      case 'codes': return t === 'codes' && !hasGift;
      case 'password': return t === 'password' && e.source !== 'generator';
      case 'generated': return t === 'password' && e.source === 'generator';
      case 'attachment': return !!(e.attachments && e.attachments.length);
      case 'pinned': return !!e.pinned;
      case 'expired': case 'expiring': {
        if (t === 'card' && e.expiry && !e.expires) return cardStatus(e.expiry, today) === (kind === 'expired' ? 'expired' : 'soon');
        if (!e.expires || !/^\d{4}-\d{2}-\d{2}$/.test(e.expires)) return false;
        if (kind === 'expired') return e.expires < today;
        const soon = iso(new Date(new Date(today + 'T00:00:00Z').getTime() + 60 * 86400000));
        return today <= e.expires && e.expires <= soon;
      }
      case 'unused': case 'used': {
        const codes = e.codes || [];
        return codes.length > 0 && codes.some((c) => !!c.used === (kind === 'used'));
      }
      default: return t === kind;
    }
  }

  function termScore(term, f, e, today) {
    const q = term.low;
    if (f.title.startsWith(q)) return [W.titleStart, 'exact'];
    if (f.title.includes(q)) return [W.title, 'exact'];
    if (f.main.includes(q)) return [W.main, 'exact'];
    if (f.tags.includes(q)) return [W.tags, 'exact'];
    if (term.kind && kindMatch(term.kind, e, today)) return [W.type, 'exact'];
    if (giftMatch(term, e)) return [W.gift, 'exact'];
    if (f.other.includes(q)) return [W.other, 'exact'];
    let best = 0;
    for (const syn of term.synonyms) {
      if (f.title.includes(syn) || f.main.includes(syn)) best = Math.max(best, W.syn);
      else if (f.tags.includes(syn) || f.other.includes(syn)) best = Math.max(best, Math.floor(W.syn / 2));
    }
    if (best) return [best, 'synonym'];
    if (term.pinyin && initials(e.title || '').some((v) => v.replace(/ /g, '').includes(q) || v.split(' ').some((w) => w.startsWith(q)))) {
      return [W.pinyin, 'pinyin'];
    }
    if (term.ascii && q.length >= 4) {
      const k = q.length >= 8 ? 2 : 1;
      for (const word of (f.title + ' ' + f.main + ' ' + f.tags).split(/[^a-z0-9.\-]+/)) {
        for (const w of [word, ...word.split('.')]) {
          if (w && Math.abs(w.length - q.length) <= k && damerauAtMost(q, w, k)) return [W.fuzzy, 'fuzzy'];
        }
      }
    }
    return [0, ''];
  }

  // [{entry, score, ways}]，按分数从高到低（分数一样的保持原来的顺序）；空查询返回 null
  function search(entries, query, today) {
    const terms = parse(query);
    if (!terms.length) return null;
    today = today || iso(new Date());
    const out = [];
    for (const e of entries) {
      const f = fieldsOf(e);
      let total = 0;
      const ways = new Set();
      let ok = true;
      for (const t of terms) {
        const [s, how] = termScore(t, f, e, today);
        if (!s) { ok = false; break; }
        total += s;
        ways.add(how);
      }
      if (ok) out.push({ entry: e, score: total, ways });
    }
    return out.sort((a, b) => b.score - a.score);
  }

  return { search, initials, damerauAtMost, cardStatus };
})();
