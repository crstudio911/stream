const X = require('./extract');

let pw = null;
let browser = null;
let launching = null;
let idleTimer = null;

function engine() {
  if (pw !== null) return pw;
  try {
    pw = require('playwright-core');
  } catch (e) {
    pw = false;
  }
  return pw;
}

async function getBrowser() {
  const p = engine();
  if (!p) throw X.fail('browser_unavailable');
  if (browser && browser.isConnected()) return browser;
  if (!launching) {
    launching = p.chromium
      .launch({
        headless: true,
        executablePath: process.env.CHROME_PATH || undefined,
        args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--mute-audio', '--autoplay-policy=no-user-gesture-required', '--disable-background-networking', '--disable-extensions', '--no-first-run']
      })
      .then((b) => {
        browser = b;
        b.on('disconnected', () => {
          browser = null;
        });
        return b;
      })
      .finally(() => {
        launching = null;
      });
  }
  try {
    return await launching;
  } catch (e) {
    throw X.fail('browser_unavailable');
  }
}

function touchIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (browser) browser.close().catch(() => {});
    browser = null;
  }, 90000);
  idleTimer.unref();
}

function available() {
  return !!engine();
}

const INIT = `
(() => {
  try {
    const mk = navigator.requestMediaKeySystemAccess;
    if (mk) navigator.requestMediaKeySystemAccess = function () { window.__popDrm = true; return mk.apply(this, arguments); };
    window.open = function () { return null; };
    const orig = HTMLMediaElement.prototype.play;
    HTMLMediaElement.prototype.play = function () { try { this.muted = true; } catch (e) {} return orig.apply(this, arguments); };
  } catch (e) {}
})();
`;

const PLAY_SELECTORS = [
  '.vjs-big-play-button', '.jw-icon-display', '.jw-display-icon-container', '.plyr__control--overlaid', '.mejs__overlay-button', '.fp-play', '.flowplayer .fp-ui',
  '.ytp-large-play-button', '.dplayer-mobile-play', '.dplayer-play-icon', '.art-state', '.video-js', '.jwplayer', '.plyr', '.play-button', '.btn-play', '.play-btn',
  '[class*="big-play"]', '[class*="play-icon"]', '[class*="PlayButton"]', '[aria-label*="play" i]', '[title*="play" i]', 'button[class*="play" i]', '[class*="poster"]', 'video'
];

async function nudge(page, deep) {
  const frames = page.frames().slice(0, deep ? 12 : 5);
  for (const f of frames) {
    try {
      await f.evaluate(() => {
        document.querySelectorAll('video').forEach((v) => {
          try {
            v.muted = true;
            const r = v.play();
            if (r && r.catch) r.catch(() => {});
          } catch (e) {}
        });
      });
    } catch (e) {}
    let clicked = false;
    for (const sel of PLAY_SELECTORS) {
      try {
        const el = await f.$(sel);
        if (!el) continue;
        await el.click({ timeout: 700, force: true, noWaitAfter: true }).catch(() => {});
        clicked = true;
        break;
      } catch (e) {}
    }
    if (!clicked) {
      try {
        await f
          .locator('button, [role=button], a, div[onclick], span[onclick]')
          .filter({ hasText: /^\s*(?:play|watch|start|تشغيل|شاهد|مشاهدة|ابدأ)\b/i })
          .first()
          .click({ timeout: 700, force: true, noWaitAfter: true });
      } catch (e) {}
    }
  }
  {
    try {
      const box = await page.evaluate(() => {
        const list = Array.from(document.querySelectorAll('iframe,video,canvas,object,embed'));
        let best = null;
        let area = 0;
        list.forEach((e) => {
          const r = e.getBoundingClientRect();
          if (r.width * r.height > area) {
            area = r.width * r.height;
            best = { x: r.left + r.width / 2, y: r.top + r.height / 2 };
          }
        });
        return best;
      });
      if (box) await page.mouse.click(Math.max(1, box.x), Math.max(1, box.y)).catch(() => {});
      await page.keyboard.press('Space').catch(() => {});
    } catch (e) {}
  }
}

async function collectTags(page, found) {
  for (const f of page.frames().slice(0, 12)) {
    try {
      const list = await f.evaluate(() => {
        const out = [];
        document.querySelectorAll('video,source').forEach((v) => {
          [v.currentSrc, v.src].forEach((s) => {
            if (s && !/^blob:|^data:/.test(s)) out.push(s);
          });
        });
        return { out, drm: !!window.__popDrm, url: location.href };
      });
      list.out.forEach((u) => {
        const abs = X.absolute(u, list.url);
        if (abs) found.items.push({ url: abs, kind: X.kindOf(abs, ''), via: 'player', referer: list.url });
      });
      if (list.drm) found.drm = true;
    } catch (e) {}
  }
}

async function findInBrowser(pageUrl, opt) {
  const budget = Math.max(6000, Math.min(60000, (Number(opt.budget) || 20) * 1000));
  const deep = !!opt.deep;
  const b = await getBrowser();
  touchIdle();
  const deadline = Date.now() + budget;
  const found = { items: [], drm: false };
  let title = '';
  const profiles = deep ? ['desktop', 'mobile'] : ['desktop'];
  for (let pi = 0; pi < profiles.length; pi++) {
    const mobile = profiles[pi] === 'mobile';
    const left = deadline - Date.now();
    if (left < 4000) break;
    const slice = pi === 0 && profiles.length > 1 ? Math.floor(left * 0.65) : left;
    const until = Date.now() + slice;
    const ctx = await b.newContext({
      userAgent: mobile ? X.UA_MOBILE : X.UA_DESKTOP,
      viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 720 },
      isMobile: mobile,
      hasTouch: mobile,
      serviceWorkers: 'block',
      acceptDownloads: false,
      ignoreHTTPSErrors: false
    });
    const own = new Set();
    try {
      await ctx.addInitScript(INIT);
      ctx.on('page', (p) => {
        setTimeout(() => {
          if (!own.has(p)) p.close().catch(() => {});
        }, 400);
      });
      await ctx.route('**/*', async (route) => {
        const req = route.request();
        const url = req.url();
        let u;
        try {
          u = new URL(url);
        } catch (e) {
          return route.abort();
        }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return route.continue();
        if (X.isAdHost(u.hostname)) return route.abort();
        const type = req.resourceType();
        if (type === 'image' || type === 'font' || type === 'websocket') return route.abort();
        try {
          await X.assertPublic(url);
        } catch (e) {
          return route.abort();
        }
        const kind = X.kindOf(url, '');
        const ref = req.headers().referer || (req.frame() && req.frame().url()) || pageUrl;
        const isSeg = /\.(ts|m4s|aac|m4a|cmfv|cmfa)(?:$|[?#])/i.test(u.pathname + u.search) && kind === '';
        if (kind && kind !== 'dash' && !X.looksLikeAd(url)) found.items.push({ url, kind, via: 'network', referer: ref });
        else if (type === 'media' && !isSeg && !X.looksLikeAd(url)) found.items.push({ url, kind: 'mp4', via: 'network', referer: ref });
        if (kind === 'dash') found.dash = true;
        if (type === 'media' || isSeg) return route.abort();
        return route.continue();
      });
      const main = await ctx.newPage();
      own.add(main);
      main.setDefaultTimeout(8000);
      try {
        await main.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: Math.min(25000, Math.max(6000, slice - 2000)) });
      } catch (e) {}
      try {
        title = title || (await main.title());
      } catch (e) {}
      let round = 0;
      let firstAt = 0;
      while (Date.now() < until) {
        await nudge(main, deep && round > 0);
        await collectTags(main, found);
        const good = found.items.filter((c) => c.kind && !X.looksLikeAd(c.url));
        if (good.length && !firstAt) firstAt = Date.now();
        if (firstAt && Date.now() - firstAt > (deep ? 3500 : 2200)) break;
        if (deep && round === 1) {
          const srcs = await main
            .evaluate(() => Array.from(document.querySelectorAll('iframe')).map((f) => f.src).filter(Boolean))
            .catch(() => []);
          for (const s of srcs.slice(0, 2)) {
            if (Date.now() > until - 4000) break;
            const sub = await ctx.newPage();
            own.add(sub);
            try {
              await sub.goto(s, { waitUntil: 'domcontentloaded', timeout: 8000, referer: pageUrl });
              await nudge(sub, true);
              await sub.waitForTimeout(1500);
              await collectTags(sub, found);
            } catch (e) {}
            await sub.close().catch(() => {});
          }
        }
        round++;
        await main.waitForTimeout(1200);
      }
      await collectTags(main, found);
    } finally {
      await ctx.close().catch(() => {});
    }
    if (found.items.some((c) => c.kind && !X.looksLikeAd(c.url))) break;
  }
  return { items: found.items, drm: found.drm, dash: !!found.dash, title };
}

async function shutdown() {
  clearTimeout(idleTimer);
  if (browser) await browser.close().catch(() => {});
  browser = null;
}

module.exports = { available, findInBrowser, shutdown };
