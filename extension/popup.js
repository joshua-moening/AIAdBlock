/* Popup: render the last scan for the active tab.
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

async function main() {
  const stateEl = document.getElementById('state');
  const urlEl = document.getElementById('url');
  const listEl = document.getElementById('list');

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  urlEl.textContent = (tab && tab.url) || '';
  if (!tab) return;

  const storage = chrome.storage.session || chrome.storage.local;
  const key = 'scan_' + tab.id;
  const data = (await storage.get(key))[key];

  if (!data || !Array.isArray(data.verdicts) || !data.verdicts.length) {
    stateEl.textContent = 'no scan yet';
    return;
  }

  stateEl.textContent = 'protected';
  stateEl.classList.add('live');

  const counted = count(data.verdicts);
  document.getElementById('blocked').textContent = counted.block;
  document.getElementById('warned').textContent = counted.warn;
  document.getElementById('allowed').textContent = counted.allow;

  const visible = data.verdicts
    .filter((v) => v.action !== 'allow')
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  listEl.replaceChildren();

  if (!visible.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = 'Nothing suspicious on this page.';
    listEl.append(p);
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
