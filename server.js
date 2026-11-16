const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const zlib = require('zlib');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const FETCH_TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_CONCURRENT_CHECKS = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const MAX_RATE_LIMIT_ENTRIES = 10000;

const INDEX_HTML_PATH = path.join(__dirname, 'index.html');
let cachedIndexHtml;
try {
  cachedIndexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
} catch (err) {
  console.error('Fatal: Unable to load index.html at startup:', err.message);
  process.exit(1);
}

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer'
};

const CSP_HEADER = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "object-src 'none'",
  "frame-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; ') + ';';

let activeChecks = 0;
const rateLimitStore = new Map();

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}, RATE_LIMIT_WINDOW_MS);
cleanupTimer.unref();

function getClientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      return forwarded.split(',')[0].trim();
    }
    const realIp = req.headers['x-real-ip'];
    if (typeof realIp === 'string' && realIp.trim()) {
      return realIp.trim();
    }
  }
  return req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(clientIp) {
  const now = Date.now();
  const existing = rateLimitStore.get(clientIp);

  if (!existing || now > existing.resetAt) {
    if (rateLimitStore.size >= MAX_RATE_LIMIT_ENTRIES) {
      const oldestKey = rateLimitStore.keys().next().value;
      if (oldestKey !== undefined) rateLimitStore.delete(oldestKey);
    }
    rateLimitStore.set(clientIp, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, retryAfterSec: 0 };
  }

  if (existing.count >= RATE_LIMIT_MAX_REQUESTS) {
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000))
    };
  }

  existing.count += 1;
  return { allowed: true, retryAfterSec: 0 };
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  res.writeHead(statusCode, {
    ...SECURITY_HEADERS,
    ...extraHeaders,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

function normaliseInputUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  if (/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

function isBlockedIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c] = parts;

  if (a === 0) return true; // 0.0.0.0/8 (Current network)
  if (a === 10) return true; // 10.0.0.0/8 (Private)
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true; // 127.0.0.0/8 (Loopback)
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local / cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (Private)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 (IETF protocol)
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 88 && c === 99) return true; // 192.88.99.0/24 (6to4 relay anycast)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 (Private)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 (TEST-NET-2)
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 (TEST-NET-3)
  if (a >= 224) return true; // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)

  return false;
}

function parseIpv6ToWords(rawIp) {
  let ip = rawIp.split('%')[0].toLowerCase();

  const lastColon = ip.lastIndexOf(':');
  if (lastColon !== -1 && ip.slice(lastColon + 1).includes('.')) {
    const ipv4Part = ip.slice(lastColon + 1);
    const octets = ipv4Part.split('.').map(Number);
    if (octets.length !== 4 || octets.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
      return null;
    }
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    ip = `${ip.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = ip.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);

  if (halves.length === 1 && left.length !== 8) return null;
  if (halves.length === 2 && missing < 1) return null;

  const fullGroups = [
    ...left,
    ...Array(Math.max(0, missing)).fill('0'),
    ...right
  ];

  if (fullGroups.length !== 8) return null;

  const words = [];
  for (const group of fullGroups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    words.push(parseInt(group, 16));
  }
  return words;
}

function isBlockedIp(rawIp) {
  const ip = rawIp.split('%')[0].toLowerCase();

  if (net.isIPv4(ip)) {
    return isBlockedIpv4(ip);
  }

  if (net.isIPv6(ip)) {
    const words = parseIpv6ToWords(ip);
    if (!words) return true;

    const isAllZeroPrefix =
      words[0] === 0 &&
      words[1] === 0 &&
      words[2] === 0 &&
      words[3] === 0 &&
      words[4] === 0;

    // :: (unspecified) and ::1 (loopback)
    if (isAllZeroPrefix && words[5] === 0 && words[6] === 0 && (words[7] === 0 || words[7] === 1)) {
      return true;
    }

    // IPv4-mapped (::ffff:0:0/96) and deprecated IPv4-compatible (::/96)
    if (isAllZeroPrefix && (words[5] === 0xffff || words[5] === 0)) {
      const embeddedIpv4 = `${(words[6] >> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >> 8) & 0xff}.${words[7] & 0xff}`;
      return isBlockedIpv4(embeddedIpv4);
    }

    // NAT64 (64:ff9b::/96 and 64:ff9b:1::/48)
    if (words[0] === 0x0064 && (words[1] === 0xff9b || words[1] === 0xff9b)) {
      if (words[1] === 0xff9b && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0) {
        const embeddedIpv4 = `${(words[6] >> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >> 8) & 0xff}.${words[7] & 0xff}`;
        return isBlockedIpv4(embeddedIpv4);
      }
      if (words[2] === 0x0001) return true;
    }

    if (words[0] === 0x0100 && words[1] === 0 && words[2] === 0 && words[3] === 0) return true; // 100::/64 Discard
    if (words[0] === 0x2001 && words[1] === 0x0000) return true; // 2001::/32 Teredo
    if (words[0] === 0x2001 && words[1] === 0x0db8) return true; // 2001:db8::/32 Documentation
    if (words[0] === 0x2002) return true; // 2002::/16 6to4
    if ((words[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique local
    if ((words[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 Link-local
    if ((words[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 Deprecated site-local
    if ((words[0] & 0xff00) === 0xff00) return true; // ff00::/8 Multicast

    return false;
  }

  return true;
}

async function validateAndResolveUrl(inputUrl) {
  let parsed;
  try {
    parsed = new URL(inputUrl);
  } catch {
    throw Object.assign(new Error('Invalid URL format.'), { statusCode: 400 });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw Object.assign(new Error('Only http:// and https:// URLs are allowed.'), { statusCode: 400 });
  }

  if (parsed.username || parsed.password) {
    throw Object.assign(new Error('URLs with embedded credentials are not allowed.'), { statusCode: 400 });
  }

  const bareHost = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!bareHost) {
    throw Object.assign(new Error('Missing hostname in URL.'), { statusCode: 400 });
  }

  const ipFamily = net.isIP(bareHost);
  if (ipFamily) {
    if (isBlockedIp(bareHost)) {
      throw Object.assign(new Error('Access to private or local IP addresses is blocked.'), { statusCode: 403 });
    }
    return {
      url: parsed,
      addresses: [{ address: bareHost, family: ipFamily }]
    };
  }

  const cleanHost = bareHost.replace(/\.+$/, '');
  if (!cleanHost.includes('.')) {
    throw Object.assign(new Error('Single-label or internal hostnames are not allowed.'), { statusCode: 400 });
  }

  let records;
  try {
    records = await dns.lookup(bareHost, { all: true, verbatim: true });
  } catch {
    throw Object.assign(new Error(`Could not resolve domain: ${bareHost}`), { statusCode: 502 });
  }

  if (!records || records.length === 0) {
    throw Object.assign(new Error(`No DNS records found for: ${bareHost}`), { statusCode: 502 });
  }

  for (const record of records) {
    if (isBlockedIp(record.address)) {
      throw Object.assign(new Error('Access to private or local network addresses is blocked.'), { statusCode: 403 });
    }
  }

  return {
    url: parsed,
    addresses: records.map(r => ({ address: r.address, family: r.family }))
  };
}

function extractCharset(contentType) {
  const match = contentType.match(/charset\s*=\s*["']?([^"';\s]+)/i);
  return match ? match[1].trim() : 'utf-8';
}

function decodeBuffer(buffer, charset) {
  try {
    return new TextDecoder(charset).decode(buffer);
  } catch {
    return new TextDecoder('utf-8').decode(buffer);
  }
}

function fetchSingleHop(resolvedTarget, deadlineMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (!settled) {
        settled = true;
        fn(value);
      }
    };

    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) {
      return finish(reject, Object.assign(new Error('Request timed out after 10 seconds.'), { statusCode: 504 }));
    }

    const { url, addresses } = resolvedTarget;
    const transport = url.protocol === 'https:' ? https : http;

    const pinnedLookup = (_hostname, options, callback) => {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      if (options && options.all) {
        return callback(null, addresses);
      }
      const first = addresses[0];
      return callback(null, first.address, first.family);
    };

    const req = transport.request(
      url,
      {
        method: 'GET',
        lookup: pinnedLookup,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; RelMeChecker/1.2)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Encoding': 'gzip, deflate, br'
        }
      },
      res => {
        const statusCode = res.statusCode || 200;

        if (statusCode >= 300 && statusCode < 400) {
          res.resume();
          return finish(resolve, {
            redirectLocation: res.headers.location || null
          });
        }

        const contentType = String(res.headers['content-type'] || '').toLowerCase();
        const isHtmlLike =
          !contentType ||
          contentType.includes('text/html') ||
          contentType.includes('application/xhtml+xml') ||
          contentType.includes('text/plain') ||
          contentType.includes('application/xml');

        if (!isHtmlLike) {
          res.resume();
          return finish(
            reject,
            Object.assign(
              new Error(`Unsupported content type: ${contentType.split(';')[0]}`),
              { statusCode: 415 }
            )
          );
        }

        const encoding = String(res.headers['content-encoding'] || '').toLowerCase().trim();
        let stream = res;

        if (encoding === 'gzip' || encoding === 'x-gzip') {
          stream = zlib.createGunzip();
        } else if (encoding === 'br') {
          stream = zlib.createBrotliDecompress();
        } else if (encoding === 'deflate') {
          stream = zlib.createInflate();
        } else if (encoding && encoding !== 'identity') {
          res.resume();
          return finish(
            reject,
            Object.assign(new Error(`Unsupported content encoding: ${encoding}`), { statusCode: 415 })
          );
        }

        if (stream !== res) {
          res.on('error', err => {
            stream.destroy();
            finish(reject, Object.assign(new Error(`Upstream stream error: ${err.message}`), { statusCode: 502 }));
          });
          res.pipe(stream);
        }

        const chunks = [];
        let totalBytes = 0;

        stream.on('data', chunk => {
          totalBytes += chunk.length;
          if (totalBytes > MAX_HTML_BYTES) {
            res.destroy();
            if (stream !== res) stream.destroy();
            return finish(
              reject,
              Object.assign(
                new Error(`Page exceeded the ${Math.round(MAX_HTML_BYTES / (1024 * 1024))} MB size limit.`),
                { statusCode: 413 }
              )
            );
          }
          chunks.push(chunk);
        });

        stream.on('end', () => {
          const fullBuffer = Buffer.concat(chunks);
          const charset = extractCharset(contentType);
          const html = decodeBuffer(fullBuffer, charset);
          finish(resolve, {
            html,
            status: statusCode,
            finalUrl: url.href
          });
        });

        stream.on('error', err => {
          res.destroy();
          finish(reject, Object.assign(new Error(`Failed to decode response: ${err.message}`), { statusCode: 502 }));
        });
      }
    );

    req.setTimeout(remainingMs, () => {
      req.destroy(Object.assign(new Error('Request timed out after 10 seconds.'), { statusCode: 504 }));
    });

    req.on('error', err => {
      if (err.statusCode) {
        return finish(reject, err);
      }
      finish(reject, Object.assign(new Error(`Failed to fetch site: ${err.message}`), { statusCode: 502 }));
    });

    req.end();
  });
}

async function safeFetchHtml(initialUrl) {
  let currentUrl = initialUrl;
  const deadlineMs = Date.now() + FETCH_TIMEOUT_MS;

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const resolvedTarget = await validateAndResolveUrl(currentUrl);
    const hopResult = await fetchSingleHop(resolvedTarget, deadlineMs);

    if ('redirectLocation' in hopResult) {
      if (!hopResult.redirectLocation) {
        throw Object.assign(new Error('Redirect response missing Location header.'), { statusCode: 502 });
      }
      if (redirects === MAX_REDIRECTS) {
        throw Object.assign(new Error('Too many redirects.'), { statusCode: 502 });
      }
      try {
        currentUrl = new URL(hopResult.redirectLocation, resolvedTarget.url.href).href;
      } catch {
        throw Object.assign(new Error('Invalid redirect Location URL.'), { statusCode: 502 });
      }
      continue;
    }

    return hopResult;
  }

  throw Object.assign(new Error('Too many redirects.'), { statusCode: 502 });
}

const server = http.createServer(async (req, res) => {
  let parsedReqUrl;
  try {
    parsedReqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    res.writeHead(400, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }

  // Health check endpoint for Docker / Coolify
  if (parsedReqUrl.pathname === '/health') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...SECURITY_HEADERS, Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Method Not Allowed');
    }
    if (req.method === 'HEAD') {
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end();
    }
    return sendJson(res, 200, { status: 'ok' });
  }

  // API endpoint to fetch target website HTML server-side
  if (parsedReqUrl.pathname === '/api/check') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { error: 'Method Not Allowed' }, { Allow: 'GET' });
    }

    const clientIp = getClientIp(req);
    const rate = checkRateLimit(clientIp);
    if (!rate.allowed) {
      return sendJson(
        res,
        429,
        { error: 'Too many requests. Please try again shortly.' },
        { 'Retry-After': String(rate.retryAfterSec) }
      );
    }

    const rawUrl = parsedReqUrl.searchParams.get('url') || '';
    const targetUrl = normaliseInputUrl(rawUrl);

    if (!targetUrl) {
      return sendJson(res, 400, { error: 'Missing URL parameter.' });
    }

    if (activeChecks >= MAX_CONCURRENT_CHECKS) {
      return sendJson(res, 503, { error: 'Server is busy handling other checks. Please retry shortly.' });
    }

    activeChecks += 1;
    try {
      const result = await safeFetchHtml(targetUrl);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, err.statusCode || 500, { error: err.message });
    } finally {
      activeChecks -= 1;
    }
  }

  // Serve index.html for the root route
  if (parsedReqUrl.pathname === '/' || parsedReqUrl.pathname === '/index.html') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...SECURITY_HEADERS, Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Method Not Allowed');
    }
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': CSP_HEADER
    });
    return res.end(req.method === 'HEAD' ? undefined : cachedIndexHtml);
  }

  res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
});

server.on('error', err => {
  console.error('Server error:', err);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`rel="me" checker running on port ${PORT}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down gracefully...`);
  clearInterval(cleanupTimer);
  server.close(() => {
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
