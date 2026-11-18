const net = require('net');
const dns = require('dns').promises;

const ALLOW_PRIVATE = process.env.STREAM_ALLOW_PRIVATE === '1';
const PORTS = new Set(['', '80', '443', '8080', '8443']);
const UA_DESKTOP = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const UA_MOBILE = 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36';
const MEDIA_EXT = /\.(m3u8|mp4|webm|m4v|mov|mpd)(?:$|[?#])/i;
const MEDIA_SCAN = /(?:https?:)?\/\/[^\s"'<>\\)\]},]+?\.(?:m3u8|mp4|webm|m4v|mov|mpd)(?:\?[^\s"'<>\\)\]},]*)?/gi;
const AD_HOSTS = [
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'google-analytics.com', 'googletagmanager.com', 'adservice.google.com',
  'adnxs.com', 'adsrvr.org', 'taboola.com', 'outbrain.com', 'popads.net', 'popcash.net', 'propellerads.com', 'exoclick.com', 'exosrv.com',
  'juicyads.com', 'trafficjunky.net', 'adsterra.com', 'highperformanceformat.com', 'hilltopads.net', 'clickadu.com', 'revcontent.com',
  'mgid.com', 'criteo.com', 'pubmatic.com', 'rubiconproject.com', 'openx.net', 'adform.net', 'moatads.com', 'scorecardresearch.com',
  'imasdk.googleapis.com', 'pagead2.googlesyndication.com', 'onclickads.net', 'onclkds.com', 'ad-maven.com', 'admaven.com', 'tsyndicate.com',
  'richpartners.com', 'yllix.com', 'a-ads.com', 'coinzilla.com', 'bidvertiser.com', 'smartadserver.com', 'amazon-adsystem.com', 'facebook.net'
];
const AD_PATH = /(?:^|[/_.-])(?:ads?|adserver|adserving|vast|vmap|preroll|pre-roll|midroll|advert|promo|sponsor|banner|tracking|beacon)(?:[/_.-]|$)/i;
const BAD_TYPE = /^(?:text\/html|application\/xhtml|image\/svg|text\/xml|application\/xml|text\/javascript|application\/javascript|application\/json)/i;

function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const p = ip.split('.').map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 0) || (p[0] === 192 && p[1] === 168) || (p[0] === 198 && (p[1] === 18 || p[1] === 19)) || p[0] >= 224;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === '::' || s === '::1') return true;
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (m) return isPrivateIp(m[1]);
    return /^(fc|fd|fe[89ab])/.test(s) || s.startsWith('64:ff9b');
  }
  return true;
}

function isAdHost(host) {
  const h = String(host || '').toLowerCase();
  return AD_HOSTS.some((d) => h === d || h.endsWith('.' + d));
}

const dnsCache = new Map();

async function assertPublic(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch (e) {
    throw fail('invalid_url');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw fail('invalid_url');
  if (u.username || u.password) throw fail('invalid_url');
  if (ALLOW_PRIVATE) return u;
  if (!PORTS.has(u.port)) throw fail('blocked_host');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan')) throw fail('blocked_host');
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw fail('blocked_host');
    return u;
  }
  const hit = dnsCache.get(host);
  if (hit && hit.until > Date.now()) {
    if (hit.bad) throw fail('blocked_host');
    return u;
  }
  let list;
  try {
    list = await dns.lookup(host, { all: true });
  } catch (e) {
    throw fail('page_unreachable');
  }
  const bad = !list.length || list.some((x) => isPrivateIp(x.address));
  if (dnsCache.size > 2000) dnsCache.clear();
  dnsCache.set(host, { until: Date.now() + 60000, bad });
  if (bad) throw fail('blocked_host');
  return u;
}

function fail(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

async function safeFetch(raw, opt) {
  opt = opt || {};
  let url = raw;
  const maxBytes = opt.maxBytes || 2000000;
  for (let hop = 0; hop <= 5; hop++) {
    await assertPublic(url);
    const headers = Object.assign({ 'User-Agent': opt.ua || UA_DESKTOP, Accept: opt.accept || '*/*', 'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8' }, opt.headers || {});
    if (opt.referer) {
      headers.Referer = opt.referer;
      try {
        headers.Origin = new URL(opt.referer).origin;
      } catch (e) {}
    }
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), opt.timeout || 15000);
    let res;
    try {
      res = await fetch(url, { headers, redirect: 'manual', signal: ac.signal });
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        try {
          await res.body.cancel();
        } catch (e) {}
        url = new URL(res.headers.get('location'), url).href;
        continue;
      }
      const type = res.headers.get('content-type') || '';
      let text = '';
      let size = 0;
      if (!opt.headOnly) {
        const reader = res.body.getReader();
        const parts = [];
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          size += r.value.length;
          parts.push(r.value);
          if (size >= maxBytes) {
            try {
              await reader.cancel();
            } catch (e) {}
            break;
          }
        }
        text = Buffer.concat(parts.map((p) => Buffer.from(p))).toString('utf8');
      } else {
        try {
          await res.body.cancel();
        } catch (e) {}
      }
      return { url, status: res.status, type, headers: res.headers, text };
    } finally {
      clearTimeout(timer);
    }
  }
  throw fail('page_unreachable');
}

function unescapeText(s) {
  return String(s)
    .replace(/\\u002[fF]/g, '/')
    .replace(/\\u0026/g, '&')
    .replace(/\\x2[fF]/g, '/')
    .replace(/\\\//g, '/')
    .replace(/&amp;/g, '&')
    .replace(/&#x2F;/gi, '/')
    .replace(/&#47;/g, '/');
}

function absolute(raw, base) {
  try {
    const s = String(raw || '').trim();
    if (!s || /^(?:blob|data|javascript|about|mailto):/i.test(s)) return '';
    const u = new URL(s, base);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    u.hash = '';
    return u.href;
  } catch (e) {
    return '';
  }
}

function kindOf(url, type) {
  let p = '';
  try {
    p = new URL(url).pathname.toLowerCase();
  } catch (e) {}
  const t = String(type || '').toLowerCase();
  if (/\.m3u8$/.test(p) || /mpegurl/.test(t)) return 'hls';
  if (/\.mpd$/.test(p) || /dash\+xml/.test(t)) return 'dash';
  if (/\.webm$/.test(p) || /video\/webm/.test(t)) return 'webm';
  if (/\.(mp4|m4v|mov)$/.test(p) || /^video\//.test(t)) return 'mp4';
  return '';
}

function looksLikeAd(url) {
  let u;
  try {
    u = new URL(url);
  } catch (e) {
    return true;
  }
  if (isAdHost(u.hostname)) return true;
  return AD_PATH.test(u.pathname);
}

function attr(tag, name) {
  const m = new RegExp('(?:^|[\\s"\'])' + name + '\\s*=\\s*("([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(tag);
  return m ? unescapeText(m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4]) : '';
}

function parseHtml(html, base) {
  const media = [];
  const frames = [];
  const add = (raw, via) => {
    const u = absolute(unescapeText(raw), base);
    if (u) media.push({ url: u, via });
  };
  const tags = (name) => html.match(new RegExp('<' + name + '\\b[^>]*>', 'gi')) || [];
  tags('video').concat(tags('source'), tags('audio')).forEach((t) => {
    ['src', 'data-src', 'data-video', 'data-url', 'data-hls', 'data-mp4'].forEach((a) => {
      const v = attr(t, a);
      if (v) add(v, 'tag');
    });
  });
  tags('meta').forEach((t) => {
    const key = (attr(t, 'property') || attr(t, 'name')).toLowerCase();
    if (/^(?:og:video(?::url|:secure_url)?|twitter:player:stream)$/.test(key)) {
      const v = attr(t, 'content');
      if (v && MEDIA_EXT.test(v)) add(v, 'meta');
    }
  });
  tags('link').forEach((t) => {
    if (/video|preload/i.test(attr(t, 'as')) && attr(t, 'href')) add(attr(t, 'href'), 'preload');
  });
  const ld = html.match(/"contentUrl"\s*:\s*"([^"]+)"/gi) || [];
  ld.forEach((x) => {
    const m = /"contentUrl"\s*:\s*"([^"]+)"/i.exec(x);
    if (m) add(m[1], 'jsonld');
  });
  const text = unescapeText(html);
  (text.match(MEDIA_SCAN) || []).forEach((m) => add(m.startsWith('//') ? 'https:' + m : m, 'script'));
  tags('iframe').forEach((t) => {
    const src = attr(t, 'src') || attr(t, 'data-src') || attr(t, 'data-lazy-src');
    const u = absolute(src, base);
    if (u && !isAdHost(new URL(u).hostname)) frames.push(u);
  });
  const title = (/<title[^>]*>([^<]{1,200})/i.exec(html) || [])[1] || '';
  return { media, frames: Array.from(new Set(frames)).slice(0, 8), title: title.replace(/\s+/g, ' ').trim() };
}

function parsePlaylist(text, base) {
  const out = { ok: /^\s*#EXTM3U/.test(text), master: false, drm: false, variants: [], encrypted: false };
  if (!out.ok) return out;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim();
    if (l.startsWith('#EXT-X-KEY') || l.startsWith('#EXT-X-SESSION-KEY')) {
      const method = (/METHOD=([A-Z0-9-]+)/.exec(l) || [])[1] || 'NONE';
      const fmt = (/KEYFORMAT="([^"]*)"/.exec(l) || [])[1] || 'identity';
      if (method === 'AES-128') out.encrypted = true;
      if (method === 'SAMPLE-AES' || method === 'SAMPLE-AES-CTR' || method === 'SAMPLE-AES-CENC' || (fmt !== 'identity' && /widevine|playready|fairplay|streamingkeydelivery|edef8ba9/i.test(fmt + ' ' + l))) out.drm = true;
    }
    if (l.startsWith('#EXT-X-STREAM-INF')) {
      out.master = true;
      let j = i + 1;
      while (j < lines.length && (!lines[j].trim() || lines[j].startsWith('#'))) j++;
      const uri = absolute(lines[j] || '', base);
      if (!uri) continue;
      const res = /RESOLUTION=(\d+)x(\d+)/.exec(l);
      const bw = Number((/(?:^|[,:])BANDWIDTH=(\d+)/.exec(l) || [])[1]) || 0;
      out.variants.push({ url: uri, height: res ? Number(res[2]) : 0, bandwidth: bw });
    }
  }
  out.variants.sort((a, b) => b.height - a.height || b.bandwidth - a.bandwidth);
  return out;
}

async function probe(cand, level) {
  const refs = [];
  [cand.referer, cand.referer ? new URL(cand.referer).origin + '/' : '', ''].forEach((r) => {
    if (refs.indexOf(r) < 0) refs.push(r);
  });
  for (const ref of refs) {
    try {
      if (cand.kind === 'hls') {
        const r = await safeFetch(cand.url, { referer: ref, maxBytes: 1500000, timeout: 12000, accept: 'application/vnd.apple.mpegurl,*/*' });
        if (r.status >= 400) continue;
        const pl = parsePlaylist(r.text, r.url);
        if (!pl.ok) continue;
        const out = { referer: ref, drm: pl.drm, encrypted: pl.encrypted };
        if (level >= 2 && pl.master) out.variants = pl.variants.slice(0, 8);
        out.master = pl.master;
        return out;
      }
      const r = await safeFetch(cand.url, { referer: ref, headers: { Range: 'bytes=0-1023' }, headOnly: true, timeout: 12000 });
      if (r.status !== 200 && r.status !== 206) continue;
      if (BAD_TYPE.test(r.type)) continue;
      const cr = /\/(\d+)$/.exec(r.headers.get('content-range') || '');
      const size = cr ? Number(cr[1]) : Number(r.headers.get('content-length')) || 0;
      if (size && size < 20000) continue;
      return { referer: ref, size };
    } catch (e) {
      if (e.code === 'blocked_host') return null;
    }
  }
  return null;
}

function rank(list) {
  const seen = new Set();
  const out = [];
  list.forEach((c) => {
    const key = c.url.split('#')[0];
    if (seen.has(key)) return;
    seen.add(key);
    out.push(c);
  });
  const weight = (c) => (c.kind === 'hls' ? (c.master ? 3 : 2) : 1) + (c.via === 'network' || c.via === 'player' ? 0.5 : 0);
  return out.sort((a, b) => weight(b) - weight(a));
}

async function staticFind(pageUrl, opt) {
  opt = opt || {};
  const found = [];
  let title = '';
  let drm = false;
  const direct = kindOf(pageUrl, '');
  if (direct) return { found: [{ url: pageUrl, kind: direct, via: 'direct', referer: '' }], title: '', pageUrl, drm };
  const page = await safeFetch(pageUrl, { maxBytes: 2500000, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' });
  if (page.status >= 400) throw fail('page_unreachable');
  if (/html|xml|text/i.test(page.type) || !page.type) {
    const p = parseHtml(page.text, page.url);
    title = p.title;
    p.media.forEach((m) => found.push({ url: m.url, kind: kindOf(m.url, ''), via: m.via, referer: page.url }));
    const frameLimit = opt.frames === undefined ? 3 : opt.frames;
    for (const f of p.frames.slice(0, frameLimit)) {
      try {
        const fr = await safeFetch(f, { referer: page.url, maxBytes: 1800000, timeout: 10000, accept: 'text/html,*/*;q=0.8' });
        if (fr.status >= 400 || !/html|text/i.test(fr.type)) continue;
        const q = parseHtml(fr.text, fr.url);
        q.media.forEach((m) => found.push({ url: m.url, kind: kindOf(m.url, ''), via: 'frame', referer: fr.url }));
      } catch (e) {}
    }
  }
  return { found, title, pageUrl: page.url, drm };
}

async function settle(found, level, max) {
  const items = [];
  let drm = false;
  let dash = false;
  const pool = rank(found.filter((c) => c.kind && c.url && !looksLikeAd(c.url)));
  for (const c of pool) {
    if (items.length >= (max || 6)) break;
    if (c.kind === 'dash') {
      dash = true;
      continue;
    }
    const p = await probe(c, level);
    if (!p) continue;
    if (p.drm) {
      drm = true;
      continue;
    }
    items.push(Object.assign({}, c, { referer: p.referer, size: p.size || 0, variants: p.variants || undefined, master: !!p.master, encrypted: !!p.encrypted }));
  }
  return { items, drm, dash };
}

module.exports = { UA_DESKTOP, UA_MOBILE, MEDIA_EXT, AD_HOSTS, isPrivateIp, isAdHost, assertPublic, safeFetch, unescapeText, absolute, kindOf, looksLikeAd, parseHtml, parsePlaylist, probe, rank, staticFind, settle, fail };
