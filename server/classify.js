/* AI AdShield classifier server.
 *
 *   POST /classify   PageScanRequest -> { verdicts: Verdict[] }
 *   GET  /health     liveness + active mode
 *   GET  /demo/*     serves the demo page
 *
 * No dependencies. Node 18+ (native fetch).
 * OWNER: Person B — prompt, taxonomy, severity policy, IOC merge.
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lookupSafeBrowsing } from './sources.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = path.resolve(__dirname, '..', 'demo');

await loadDotEnv();

const PORT = Number(process.env.PORT || 8787);
const BASE_URL = (process.env.AI_BASE_URL || 'https://api.openai.com/v1').replace(/\/+$/, '');
const API_KEY = process.env.AI_API_KEY || '';
const MODEL = process.env.AI_MODEL || 'gpt-4o-mini';

const MAX_CANDIDATES = 80;

const VERDICTS = new Set([
  'malicious',
  'deceptive',
  'phishing',
  'unwanted_redirect',
  'tracker',
  'benign_ad',
  'legit',
]);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'none']);
const ACTIONS = new Set(['block', 'warn', 'allow']);

const SYSTEM_PROMPT = `You are a web-security classifier inspecting candidates from a rendered web page.
Decide whether each candidate is a malicious/deceptive ad, a benign ad, or legitimate content.

Threat taxonomy (verdict):
- malicious: delivers or attempts to deliver malware, an exploit, or a harmful download
- deceptive: fake warnings, fake prizes, tech-support scams, fake software updates
- phishing: credential harvesting or brand impersonation with a login/verify flow
- unwanted_redirect: forces navigation or opens unexpected windows
- tracker: pure tracking pixel, beacon, or fingerprinting script
- benign_ad: ordinary commercial advertisement
- legit: not an ad, normal page content

Rules:
- Use ONLY the ids provided. Never invent ids. Return exactly one object per candidate.
- Judge from structure, origin, text, geometry and redirect chains.
- Scary urgency text PLUS a download or password field is a strong malicious signal.
- First-party editorial content that merely mentions "ad" is legit.
- When uncertain, choose the lower severity but explain the doubt in the reason.
- severity: critical | high | medium | low | none
- action: block (ads/trackers/threats), warn (suspicious, not certain), allow (legit)

Return STRICT JSON, no markdown:
{"verdicts":[{"id":"n1","verdict":"benign_ad","severity":"low","confidence":0.8,"indicators":["short evidence"],"action":"block","reason":"one sentence"}]}`;

/* ---------------------------------------------------------------- model call */

async function callModel(payload) {
  const body = {
    model: MODEL,
    temperature: 0,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      {
        role: 'user',
        content: JSON.stringify({ url: payload.url, candidates: payload.candidates }),
      },
    ],
  };

  const response = await fetch(`${BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${API_KEY}`,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`model ${response.status}: ${(await response.text()).slice(0, 300)}`);
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || '';
  return parseJson(text);
}

function parseJson(text) {
  const cleaned = String(text)
    .replace(/^```(?:json)?/i, '')
    .replace(/```\s*$/, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start >= 0 && end > start) return JSON.parse(cleaned.slice(start, end + 1));
    throw new Error('model returned non-JSON');
  }
}

/* ------------------------------------------------------------ normalization */

function normalize(list, candidates) {
  const byId = new Map(
    (Array.isArray(list) ? list : []).map((v) => [String(v?.id), v])
  );

  return candidates.map((c) => {
    const v = byId.get(c.id) || {};
    return {
      id: c.id,
      verdict: VERDICTS.has(v.verdict) ? v.verdict : 'legit',
      severity: SEVERITIES.has(v.severity) ? v.severity : 'none',
      confidence: clamp(Number(v.confidence) || 0),
      indicators: Array.isArray(v.indicators)
        ? v.indicators.slice(0, 5).map((x) => String(x).slice(0, 160))
        : [],
      action: ACTIONS.has(v.action) ? v.action : 'allow',
      reason: typeof v.reason === 'string' ? v.reason.slice(0, 240) : '',
    };
  });
}

/* ------------------------------------------------------------- heuristic mode */

function heuristicVerdict(c) {
  const text = (c.textSnippet || '').toLowerCase();
  const classes = (c.classes || []).join(' ').toLowerCase();

  const lure =
    /out of date|update (your )?(chrome|browser|flash)|your (pc|computer|device) is infected|download (now|the update)|verify your account|claim your prize/.test(
      text
    );
  const adish =
    /sponsored|advertisement|promoted/.test(text) ||
    /(^|[-_])(ad|ads|sponsor|promo|banner|dfp)/.test(classes) ||
    c.isIframe;
  // Editorial/legal notices often carry ad-like class names ("banner").
  const notice = /privacy policy|terms of service|cookie (settings|policy)|manage (your )?preferences|site notice/.test(
    text
  );

  if (notice && !lure) {
    return {
      id: c.id,
      verdict: 'legit',
      severity: 'none',
      confidence: 0.6,
      indicators: ['site notice, not an ad'],
      action: 'allow',
      reason: 'Editorial or legal notice with an ad-like class name',
    };
  }
  if (lure && (c.hasDownload || c.hasPasswordField)) {
    return {
      id: c.id,
      verdict: 'malicious',
      severity: 'high',
      confidence: 0.7,
      indicators: ['social-engineering lure', 'risky download or password form'],
      action: 'block',
      reason: 'Update/scam lure combined with a dangerous action',
    };
  }
  if (lure) {
    return {
      id: c.id,
      verdict: 'deceptive',
      severity: 'medium',
      confidence: 0.6,
      indicators: ['social-engineering lure'],
      action: 'warn',
      reason: 'Deceptive urgency language',
    };
  }
  if (adish) {
    return {
      id: c.id,
      verdict: 'benign_ad',
      severity: 'low',
      confidence: 0.5,
      indicators: ['ad-like structure'],
      action: 'block',
      reason: 'Looks like an advertisement',
    };
  }
  return {
    id: c.id,
    verdict: 'legit',
    severity: 'none',
    confidence: 0.4,
    indicators: [],
    action: 'allow',
    reason: 'No threat indicators',
  };
}

/* ---------------------------------------------------------------- classify */

async function classify(payload) {
  const candidates = Array.isArray(payload?.candidates)
    ? payload.candidates.slice(0, MAX_CANDIDATES)
    : [];
  if (!candidates.length) return [];

  let verdicts = null;
  let mode = 'heuristic';

  if (API_KEY) {
    try {
      const raw = await callModel({ url: payload.url, candidates });
      verdicts = normalize(raw.verdicts, candidates);
      mode = MODEL;
    } catch (error) {
      console.warn('[classify] model failed, falling back:', error.message);
    }
  }

  if (!verdicts) verdicts = candidates.map(heuristicVerdict);

  // Threat-intel overlay: never let the model overrule a known IOC.
  const urls = [
    ...new Set(candidates.map((c) => c.origin).filter(Boolean)),
    payload?.url,
  ].filter(Boolean);

  if (urls.length) {
    const iocs = await lookupSafeBrowsing(urls);
    if (iocs.size) {
      for (const verdict of verdicts) {
        const candidate = candidates.find((c) => c.id === verdict.id);
        const threat = candidate && iocs.get(candidate.origin);
        if (!threat) continue;
        verdict.verdict = 'malicious';
        verdict.severity = 'critical';
        verdict.action = 'block';
        verdict.indicators = [...new Set([...verdict.indicators, `threat intel: ${threat}`])];
        verdict.reason = 'Listed in Google Safe Browsing';
      }
    }
  }

  console.log(
    `[classify] ${candidates.length} candidates via ${mode}` +
      ` -> ${verdicts.filter((v) => v.action === 'block').length} blocked, ` +
      `${verdicts.filter((v) => v.action === 'warn').length} warned`
  );

  return verdicts;
}

/* ---------------------------------------------------------------- http server */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders());
      return res.end();
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/health') {
      return json(res, 200, {
        ok: true,
        mode: API_KEY ? MODEL : 'heuristic-fallback',
        safeBrowsing: Boolean(process.env.SAFE_BROWSING_KEY),
      });
    }

    if (url.pathname === '/classify' && req.method === 'POST') {
      const payload = await readJson(req);
      const verdicts = await classify(payload);
      return json(res, 200, { verdicts });
    }

    if (url.pathname === '/demo' || url.pathname.startsWith('/demo/')) {
      return serveDemo(url.pathname, res);
    }

    if (url.pathname === '/') {
      res.writeHead(302, { location: '/demo/' });
      return res.end();
    }

    return json(res, 404, { error: 'not found' });
  } catch (error) {
    console.error('[server]', error);
    return json(res, 500, { error: String(error.message || error) });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  AI AdShield classifier on http://127.0.0.1:${PORT}`);
  console.log(`  Demo page            http://127.0.0.1:${PORT}/demo/`);
  console.log(`  Mode                 ${API_KEY ? MODEL : 'heuristic-fallback (set AI_API_KEY to enable AI)'}`);
  console.log(`  Safe Browsing        ${process.env.SAFE_BROWSING_KEY ? 'enabled' : 'disabled'}\n`);
});

/* ------------------------------------------------------------------ helpers */

async function serveDemo(pathname, res) {
  const relative = pathname.replace(/^\/demo\/?/, '') || 'index.html';
  const file = path.resolve(DEMO_DIR, relative);

  if (file !== DEMO_DIR && !file.startsWith(DEMO_DIR + path.sep)) {
    return json(res, 403, { error: 'forbidden' });
  }

  try {
    const data = await readFile(file);
    res.writeHead(200, {
      'content-type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(data);
  } catch {
    return json(res, 404, { error: 'demo file not found' });
  }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...corsHeaders() });
  res.end(JSON.stringify(value));
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
  };
}

function clamp(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

async function loadDotEnv() {
  try {
    const raw = await readFile(path.resolve(__dirname, '.env'), 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (match && process.env[match[1]] === undefined) {
        process.env[match[1]] = match[2].replace(/^["']|["']$/g, '');
      }
    }
  } catch {
    // no .env file: rely on real environment variables
  }
}
