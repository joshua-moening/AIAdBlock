/* Background service worker.
 *
 * Responsibilities:
 *   - observe redirect chains (webRequest, observational only in MV3)
 *   - call the classifier server
 *   - fall back to local heuristics when the server is down
 *   - persist the last scan per tab for the popup
 *
 * OWNER: Person B (server contract) / Person A (message plumbing).
 */

const CLASSIFY_URL = 'http://127.0.0.1:8787/classify';
const MAX_REDIRECTS_PER_TAB = 20;
const AD_HOSTS =
  /doubleclick|googlesyndication|googleadservices|adnxs|taboola|outbrain|criteo|pubmatic|amazon-adsystem|moatads|adsrvr|rubiconproject|openx|casalemedia/i;

/** tabId -> Array<{ from, to, ts }> */
const redirects = new Map();

if (chrome.webRequest && chrome.webRequest.onBeforeRedirect) {
  chrome.webRequest.onBeforeRedirect.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const list = redirects.get(details.tabId) || [];
      list.push({ from: details.url, to: details.redirectUrl, ts: Date.now() });
      while (list.length > MAX_REDIRECTS_PER_TAB) list.shift();
      redirects.set(details.tabId, list);
    },
    { urls: ['<all_urls>'] }
  );
}

const store = chrome.storage.session || chrome.storage.local;

/* Keep the toolbar badge in sync with the protection toggle. */
async function syncBadge() {
  try {
    const stored = await chrome.storage.local.get({ enabled: true });
    const on = stored.enabled !== false;
    await chrome.action.setBadgeText({ text: on ? '' : 'OFF' });
    await chrome.action.setBadgeBackgroundColor({ color: on ? '#2c5a48' : '#6b7280' });
  } catch (error) {
    console.warn('[Apollo AdShield] badge sync failed', error);
  }
}

chrome.runtime.onInstalled.addListener(syncBadge);
chrome.runtime.onStartup.addListener(syncBadge);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && 'enabled' in changes) syncBadge();
});
syncBadge();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'SCAN') return undefined;
  handleScan(message, sender)
    .then(sendResponse)
    .catch((error) => {
      console.warn('[Apollo AdShield] scan failed', error);
      sendResponse({ verdicts: [] });
    });
  return true; // keep the channel open for the async response
});

async function handleScan(message, sender) {
  // Defense in depth: never do work while protection is off.
  try {
    const stored = await chrome.storage.local.get({ enabled: true });
    if (stored.enabled === false) return { verdicts: [] };
  } catch {
    // storage unavailable: fail open to the scan rather than break the page
  }

  const tabId = sender.tab?.id;
  const chain = tabId != null ? redirects.get(tabId) || [] : [];
  const redirectChain = chain.slice(-5).map((hop) => hop.to);

  const candidates = (message.candidates || []).map((c) => ({ ...c, redirectChain }));

  let verdicts;
  try {
    const response = await fetch(CLASSIFY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: message.url, candidates }),
    });
    if (!response.ok) throw new Error(`classifier ${response.status}`);
    const data = await response.json();
    verdicts = data.verdicts;
    if (!Array.isArray(verdicts)) throw new Error('bad classifier response');
  } catch (error) {
    console.warn('[Apollo AdShield] classifier unavailable, using local fallback:', error.message);
    verdicts = localFallback(candidates);
  }

  if (tabId != null) {
    try {
      await store.set({
        ['scan_' + tabId]: {
          tabId,
          url: message.url,
          at: Date.now(),
          verdicts: withTargets(verdicts, candidates),
        },
      });
    } catch (error) {
      console.warn('[Apollo AdShield] could not persist scan', error);
    }
  }

  return { verdicts };
}

/* Attach a snapshot of the element each verdict judged, for the popup's details view. */
function withTargets(verdicts, candidates) {
  const byId = new Map(candidates.map((c) => [c.id, c]));
  return verdicts.map((v) => {
    const c = byId.get(v.id);
    if (!c) return v;
    return {
      ...v,
      target: {
        tag: c.tag,
        role: c.role || '',
        classes: c.classes || [],
        origin: c.origin || '',
        size: c.size || '',
        position: c.position || '',
        textSnippet: c.textSnippet || '',
        isIframe: !!c.isIframe,
        hasDownload: !!c.hasDownload,
        hasPasswordField: !!c.hasPasswordField,
        formAction: c.formAction || '',
        redirectChain: c.redirectChain || [],
      },
    };
  });
}

/* Last-resort classifier. Must always block the demo's malicious ad. */
function localFallback(candidates) {
  return candidates.map((c) => {
    const text = (c.textSnippet || '').toLowerCase();
    const classes = (c.classes || []).join(' ').toLowerCase();

    const lure =
      /out of date|update (your )?(chrome|browser|flash)|your (pc|computer|device) is infected|download (now|the update)|verify your account|claim your prize/.test(
        text
      );
    const adish =
      /sponsored|advertisement|promoted/.test(text) ||
      /(^|[-_])(ad|ads|sponsor|promo|banner|dfp)/.test(classes) ||
      (c.isIframe && AD_HOSTS.test(c.origin || ''));
    // Editorial/legal notices often carry ad-like class names ("banner").
    const notice =
      /privacy policy|terms of service|cookie (settings|policy)|manage (your )?preferences|site notice/.test(
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
  });
}
