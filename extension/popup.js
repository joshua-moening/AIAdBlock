/* Popup: protection toggle + render the last scan for the active tab.
 * OWNER: Person C.
 */

const LABELS = {
  malicious: 'Malicious',
  deceptive: 'Deceptive',
  phishing: 'Phishing',
  unwanted_redirect: 'Unwanted redirect',
  tracker: 'Tracker',
  benign_ad: 'Advertisement',
  legit: 'Legitimate',
};

const DEFAULT_ENABLED = true;

let activeTab = null;
let enabled = DEFAULT_ENABLED;

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || null;
  document.getElementById('url').textContent = (tab && tab.url) || '';

  const stored = await chrome.storage.local.get({ enabled: DEFAULT_ENABLED });
  enabled = stored.enabled !== false;
  applyToggleUI();

  document.getElementById('toggle').addEventListener('click', onToggle);

  if (!enabled) {
    renderOff();
    return;
  }
  await renderReport();
}

function applyToggleUI() {
  const toggle = document.getElementById('toggle');
  const state = document.getElementById('state');
  toggle.setAttribute('aria-checked', String(enabled));
  state.textContent = enabled ? 'on' : 'off';
  state.classList.toggle('live', enabled);
  state.classList.toggle('off', !enabled);
}

async function onToggle() {
  enabled = !enabled;
  await chrome.storage.local.set({ enabled });
  applyToggleUI();

  if (!enabled) {
    renderOff();
    return;
  }

  showMessage('Scanning…');
  // The content script rescans on its own; give it a beat, then re-read.
  setTimeout(() => {
    if (enabled) renderReport().catch(() => {});
  }, 1200);
}

function renderOff() {
  document.getElementById('blocked').textContent = '0';
  document.getElementById('warned').textContent = '0';
  document.getElementById('allowed').textContent = '0';
  showMessage('Protection is off. Ads and threats are not being blocked.');
}

function showMessage(text) {
  const listEl = document.getElementById('list');
  listEl.replaceChildren();
  const p = document.createElement('p');
  p.className = 'empty';
  p.textContent = text;
  listEl.append(p);
}

async function renderReport() {
  if (!enabled || !activeTab) return;

  const storage = chrome.storage.session || chrome.storage.local;
  const key = 'scan_' + activeTab.id;
  const data = (await storage.get(key))[key];

  if (!data || !Array.isArray(data.verdicts) || !data.verdicts.length) {
    showMessage('No scan for this tab yet. Reload the page.');
    return;
  }

  const counted = count(data.verdicts);
  document.getElementById('blocked').textContent = counted.block;
  document.getElementById('warned').textContent = counted.warn;
  document.getElementById('allowed').textContent = counted.allow;

  const visible = data.verdicts
    .filter((v) => v.action !== 'allow')
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const listEl = document.getElementById('list');
  listEl.replaceChildren();

  if (!visible.length) {
    showMessage('Nothing suspicious on this page.');
    return;
  }

  for (const verdict of visible) {
    listEl.append(renderItem(verdict));
  }
}

function count(verdicts) {
  return verdicts.reduce(
    (acc, v) => {
      if (v.action === 'block') acc.block += 1;
      else if (v.action === 'warn') acc.warn += 1;
      else acc.allow += 1;
      return acc;
    },
    { block: 0, warn: 0, allow: 0 }
  );
}

function severityRank(sev) {
  return { critical: 4, high: 3, medium: 2, low: 1, none: 0 }[sev] || 0;
}

function renderItem(verdict) {
  const item = document.createElement('div');
  item.className = 'item';

  const head = document.createElement('div');
  head.className = 'item-head';

  const name = document.createElement('span');
  name.className = 'verdict';
  name.textContent = LABELS[verdict.verdict] || verdict.verdict;

  const sev = document.createElement('span');
  sev.className = 'sev ' + (verdict.severity || 'none');
  sev.textContent = verdict.severity || 'none';

  head.append(name, sev);
  item.append(head);

  if (verdict.reason) {
    const reason = document.createElement('div');
    reason.className = 'reason';
    reason.textContent = verdict.reason;
    item.append(reason);
  }

  if (Array.isArray(verdict.indicators) && verdict.indicators.length) {
    const ul = document.createElement('ul');
    ul.className = 'indicators';
    for (const indicator of verdict.indicators.slice(0, 4)) {
      const li = document.createElement('li');
      li.textContent = indicator;
      ul.append(li);
    }
    item.append(ul);
  }

  return item;
}

main().catch((error) => {
  const stateEl = document.getElementById('state');
  if (stateEl) stateEl.textContent = 'error';
  console.error('[AI AdShield] popup failed', error);
});
