/* Candidate extraction heuristics.
 * Runs in the content-script isolated world before content.js.
 * Exposes window.AIAdShield.extractCandidates().
 *
 * OWNER: Person A. Keep this fast (< 15 ms on a normal page).
 */
(() => {
  const ns = (window.AIAdShield = window.AIAdShield || {});

  const MAX_CANDIDATES = 60;
  const MAX_CLASS_SCAN = 3000;

  const AD_HINT =
    /(^|[-_\s])(ad|ads|advert|advertisement|adslot|ad-slot|ad-unit|sponsor|sponsored|promo|promoted|dfp|banner|native-ad)([-_\s]|$)/i;

  const AD_SELECTORS = [
    'ins.adsbygoogle',
    '[data-ad]',
    '[data-ad-slot]',
    '[data-ad-unit]',
    '[id^="google_ads"]',
    '[id^="div-gpt-ad"]',
    '[aria-label*="advert" i]',
    '[aria-label*="sponsor" i]',
    'iframe[src*="doubleclick"]',
    'iframe[src*="googlesyndication"]',
  ].join(',');

  const DOWNLOAD_SELECTOR =
    'a[download],a[href$=".exe"],a[href$=".dmg"],a[href$=".zip"],a[href$=".msi"]';

  let seq = 0;

  function safeClassList(el) {
    if (el.classList && el.classList.length) return [...el.classList].slice(0, 8);
    return [];
  }

  function attrString(el) {
    const parts = [];
    for (const name of ['id', 'class', 'aria-label', 'data-ad', 'data-testid', 'data-ad-slot']) {
      const value = el.getAttribute && el.getAttribute(name);
      if (typeof value === 'string') parts.push(value);
    }
    return parts.join(' ');
  }

  function looksAdish(el) {
    return AD_HINT.test(attrString(el));
  }

  function isVisible(el) {
    if (!el.isConnected) return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function textOf(el) {
    if (typeof el.innerText !== 'string') return '';
    return el.innerText.replace(/\s+/g, ' ').trim().slice(0, 160);
  }

  function originOf(el) {
    const raw = el.getAttribute('src') || el.getAttribute('href') || '';
    if (!raw) return '';
    try {
      return new URL(raw, location.href).origin;
    } catch {
      return '';
    }
  }

  function depthOf(el) {
    let depth = 0;
    let node = el;
    while ((node = node.parentElement)) depth += 1;
    return depth;
  }

  function suspicion(el) {
    let score = 0;
    if (looksAdish(el)) score += 3;
    if (el.matches(AD_SELECTORS)) score += 3;
    if (el.tagName === 'IFRAME') score += 2;
    if (el.querySelector(DOWNLOAD_SELECTOR)) score += 3;
    if (el.querySelector('input[type="password"]')) score += 2;
    if (/sponsored|advertisement|promoted/i.test(textOf(el))) score += 2;

    const style = getComputedStyle(el);
    if ((style.position === 'fixed' || style.position === 'sticky') && parseInt(style.zIndex || '0', 10) > 10) {
      score += 2;
    }
    return score;
  }

  ns.extractCandidates = function extractCandidates(root = document) {
    const viewportArea = Math.max(1, innerWidth * innerHeight);
    const found = new Set();

    root.querySelectorAll(AD_SELECTORS).forEach((el) => found.add(el));
    root.querySelectorAll('iframe').forEach((el) => found.add(el));

    // Bounded attribute scan for obfuscated/partial matches.
    let scanned = 0;
    for (const el of root.querySelectorAll('[class],[id]')) {
      if (++scanned > MAX_CLASS_SCAN) break;
      if (looksAdish(el)) found.add(el);
    }

    // Prefer the outermost container: drop candidates nested inside another
    // candidate, otherwise a single ad slot produces a dozen noisy children.
    const ordered = [...found].sort((a, b) => depthOf(a) - depthOf(b));
    const topLevel = [];
    for (const el of ordered) {
      if (topLevel.some((outer) => outer !== el && outer.contains(el))) continue;
      topLevel.push(el);
    }

    const elements = new Map();
    const candidates = [];

    for (const el of topLevel) {
      if (candidates.length >= MAX_CANDIDATES) break;
      if (!isVisible(el)) continue;
      if (suspicion(el) < 2) continue;

      const rect = el.getBoundingClientRect();
      // Never hide something that covers most of the page.
      if (rect.width * rect.height > viewportArea * 0.7) continue;

      const id = 'n' + ++seq;
      elements.set(id, el);

      candidates.push({
        id,
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute('role') || '',
        classes: safeClassList(el),
        origin: originOf(el),
        size: `${Math.round(rect.width)}x${Math.round(rect.height)}`,
        position: getComputedStyle(el).position,
        textSnippet: textOf(el),
        isIframe: el.tagName === 'IFRAME',
        hasDownload: !!el.querySelector(DOWNLOAD_SELECTOR) || el.matches(DOWNLOAD_SELECTOR),
        hasPasswordField: !!el.querySelector('input[type="password"]'),
        formAction: el.querySelector('form[action]')?.action || '',
      });
    }

    return { candidates, elements };
  };

  ns.HIDE_CLASS = 'aiadblock-hide';
})();
