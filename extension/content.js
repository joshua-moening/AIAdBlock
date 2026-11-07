/* Content script: extract candidates, hide immediately, reveal on verdict.
 *
 * Flow:
 *   1. heuristics.js produces candidates + element map
 *   2. Hide every NEW candidate with CSS (no flash of malicious content)
 *   3. Ask background.js for verdicts (AI + IOC + fallback)
 *   4. Reveal anything allowed; annotate the rest with the reason
 *
 * Each element is processed once (WeakSet), so dynamic ads added later are
 * scanned without re-flickering elements we already judged.
 *
 * OWNER: Person A.
 */
(() => {
  const HIDE = window.AIAdShield.HIDE_CLASS;
  const SAFETY_TIMEOUT_MS = 6000;

  const processed = new WeakSet();
  let debounceTimer = null;
  let safetyTimer = null;

  function hide(el) {
    el.classList.add(HIDE);
  }

  function reveal(el) {
    el.classList.remove(HIDE);
  }

  function annotate(el, verdict) {
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

  async function scan() {
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
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      scan().catch(() => {});
    }, 800);
  }

  function boot() {
    scan().catch(() => {});

    const observer = new MutationObserver(queueScan);
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
