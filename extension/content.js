/* Content script: extract candidates, hide immediately, reveal on verdict.
 *
 * Flow:
 *   1. heuristics.js produces candidates + element map
 *   2. Hide every NEW candidate with CSS (no flash of malicious content)
 *   3. Ask background.js for verdicts (AI + IOC + fallback)
 *   4. Reveal anything allowed; annotate the rest with the reason
 *
 * Protection can be toggled from the popup. The state lives in
 * chrome.storage.local under `enabled`; every frame listens for changes.
 *
 * OWNER: Person A.
 */
(() => {
  const HIDE = window.AIAdShield.HIDE_CLASS;
  const SAFETY_TIMEOUT_MS = 6000;

  const processed = new Set();
  let enabled = true;
  let debounceTimer = null;
  let safetyTimer = null;

  function hide(el) {
    el.classList.add(HIDE);
  }

  function reveal(el) {
    el.classList.remove(HIDE);
  }

  function annotate(el, verdict) {
    // Preserve any title the page already had so we can restore it later.
    if (!el.hasAttribute('data-aiadblock-original-title')) {
      el.setAttribute('data-aiadblock-original-title', el.getAttribute('title') || '');
    }
    el.dataset.aiadblockVerdict = verdict.verdict;
    el.dataset.aiadblockSeverity = verdict.severity;

    const indicators = (verdict.indicators || []).join('\n• ');
    el.title = [
      `AI AdShield: ${verdict.verdict} (${verdict.severity})`,
      verdict.reason || '',
      indicators ? `• ${indicators}` : '',
    ]
      .filter(Boolean)
      .join('\n');
  }

  function clearAnnotations() {
    for (const el of document.querySelectorAll('[data-aiadblock-verdict]')) {
      el.classList.remove(HIDE);

      if (el.hasAttribute('data-aiadblock-original-title')) {
        const original = el.getAttribute('data-aiadblock-original-title');
        if (original) el.setAttribute('title', original);
        else el.removeAttribute('title');
        el.removeAttribute('data-aiadblock-original-title');
      }

      delete el.dataset.aiadblockVerdict;
      delete el.dataset.aiadblockSeverity;
    }
    // Also reveal candidates hidden while a verdict was still in flight.
    for (const el of document.querySelectorAll('.' + HIDE)) el.classList.remove(HIDE);
  }

  async function scan() {
    if (!enabled) return;

    const { candidates, elements } = window.AIAdShield.extractCandidates();

    // Only judge elements we have not seen in a previous pass.
    const fresh = candidates.filter((c) => {
      const el = elements.get(c.id);
      return el && !processed.has(el);
    });
    if (!fresh.length) return;

    // 1. Fail-safe: hide first so nothing malicious renders while we think.
    for (const c of fresh) hide(elements.get(c.id));

    // 2. If the background hangs, reveal rather than leave the page broken.
    clearTimeout(safetyTimer);
    safetyTimer = setTimeout(() => {
      for (const c of fresh) {
        const el = elements.get(c.id);
        if (!el) continue;
        reveal(el);
        processed.add(el);
      }
    }, SAFETY_TIMEOUT_MS);

    let response = null;
    try {
      response = await chrome.runtime.sendMessage({
        type: 'SCAN',
        url: location.href,
        candidates: fresh,
      });
    } catch {
      response = null;
    }

    clearTimeout(safetyTimer);

    // Protection was switched off while we were waiting: leave the page alone.
    if (!enabled) return;

    const verdicts = (response && response.verdicts) || [];
    const byId = new Map(verdicts.map((v) => [v.id, v]));

    for (const c of fresh) {
      const el = elements.get(c.id);
      if (!el) continue;
      const verdict = byId.get(c.id);

      if (!verdict || verdict.action === 'allow') {
        reveal(el);
      } else {
        hide(el);
        annotate(el, verdict);
      }
      processed.add(el);
    }
  }

  function queueScan() {
    if (!enabled) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      scan().catch(() => {});
    }, 800);
  }

  function setEnabled(next) {
    if (next === enabled) return;
    enabled = next;

    clearTimeout(debounceTimer);
    clearTimeout(safetyTimer);

    if (!enabled) {
      processed.clear();
      clearAnnotations();
      return;
    }

    // Re-enabling: start from a clean slate and scan the current DOM.
    processed.clear();
    clearAnnotations();
    scan().catch(() => {});
  }

  async function readEnabled() {
    try {
      const stored = await chrome.storage.local.get({ enabled: true });
      return stored.enabled !== false;
    } catch {
      return true;
    }
  }

  async function boot() {
    enabled = await readEnabled();
    if (enabled) scan().catch(() => {});

    const observer = new MutationObserver(queueScan);
    observer.observe(document.documentElement, { childList: true, subtree: true });

    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local' || !('enabled' in changes)) return;
      setEnabled(changes.enabled.newValue !== false);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
