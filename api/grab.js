// api/grab.js
// Safer cookie handling for invalid/edge "expires" values.
// Supports ?browser=true as before (requires puppeteer-core + chromium on deploy).

const axios = require('axios');
const { wrapper } = require('axios-cookiejar-support');
const tough = require('tough-cookie');
const valid = require('valid-url');

async function runBrowser(url) {
  // lazy require so normal http mode stays fast
  const chromium = require('@sparticuz/chromium-min');
  const puppeteer = require('puppeteer-core');

  const executablePath = await chromium.executablePath();
  const browser = await puppeteer.launch({
    args: chromium.args,
    defaultViewport: chromium.defaultViewport,
    executablePath,
    headless: true,
  });

  const page = await browser.newPage();
  await page.setUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
  );

  await page.goto(url, { waitUntil: 'networkidle2', timeout: 25_000 });

  const cookies = await page.cookies();
  const docCookie = await page.evaluate(() => document.cookie);
  await browser.close();

  return {
    mode: 'browser',
    cookies,
    documentCookie: docCookie,
  };
}

/**
 * Safe helper: returns ISO string for a Date if valid, otherwise null.
 */
function safeDateToISOString(maybeDate) {
  try {
    if (!maybeDate) return null;
    // tough-cookie sometimes stores "Infinity" or other values.
    // If it's already a Date object, check getTime()
    if (maybeDate instanceof Date) {
      if (!isNaN(maybeDate.getTime())) return maybeDate.toISOString();
      return null;
    }
    // If it's a number (seconds?), try to coerce
    if (typeof maybeDate === 'number') {
      const d = new Date(maybeDate);
      if (!isNaN(d.getTime())) return d.toISOString();
      return null;
    }
    // Some cookie libs may give strings — try Date parsing but guard invalid
    const d = new Date(maybeDate);
    if (!isNaN(d.getTime())) return d.toISOString();
    return null;
  } catch (e) {
    return null;
  }
}

module.exports = async (req, res) => {
  // CORS for testing; tighten in production
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const target = (req.query && req.query.url) || '';
  const useBrowser = String(req.query?.browser || '').toLowerCase() === 'true';

  if (!valid.isWebUri(target)) {
    return res.status(400).json({ ok: false, error: 'Provide a valid ?url=https://...' });
  }

  try {
    if (useBrowser) {
      const out = await runBrowser(target);
      return res.status(200).json({ ok: true, url: target, ...out });
    }

    // http-only fast path
    const jar = new tough.CookieJar();
    const client = wrapper(
      axios.create({
        jar,
        withCredentials: true,
        timeout: 15_000,
        maxRedirects: 10,
        headers: {
          'User-Agent': 'Mozilla/5.0 (cookie-grabber vercel)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        validateStatus: (s) => s >= 200 && s < 400,
      })
    );

    const resp = await client.get(target);

    const setCookieHeader = resp.headers['set-cookie'] || [];

    // getCookies may throw in weird edge cases; guard it
    let stored = [];
    try {
      stored = await jar.getCookies(target);
    } catch (innerErr) {
      console.warn('Warning: jar.getCookies failed - continuing with empty cookie list', innerErr && innerErr.stack ? innerErr.stack : innerErr);
      stored = [];
    }

    // normalize cookies safely
    const cookies = (stored || []).map((c) => {
      // tough-cookie Cookie instances differ across versions; handle common props
      const name = c.key || c.name || (typeof c === 'string' ? c.split('=')[0] : null);
      const value = c.value || null;
      const domain = c.domain || null;
      const path = c.path || null;
      // c.expires might be a Date, number, string, or the string 'Infinity' — use safe helper
      const expires = safeDateToISOString(c.expires);
      const httpOnly = !!c.httpOnly;
      const secure = !!c.secure;
      const sameSite = c.sameSite || null;

      return { name, value, domain, path, expires, httpOnly, secure, sameSite, raw: String(c) };
    });

    return res.status(200).json({
      ok: true,
      url: target,
      mode: 'http',
      status: resp.status,
      setCookieHeader,
      cookies,
    });
  } catch (err) {
    // log stack for debugging
    console.error('grab error:', err && err.stack ? err.stack : err);
    return res.status(500).json({ ok: false, error: String(err && err.message ? err.message : err) });
  }
};
