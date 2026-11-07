# Apollo AdShield

**Hackathon theme:** AI in Cyber Security

A client-side threat-detection layer for untrusted third-party web content.
Blocklists catch known malicious ads. **Apollo AdShield uses AI to catch the novel,
deceptive and malicious ones — and explains why, before they execute.**

---

## Quickstart (5 minutes)

**Prerequisite:** Node.js 18+ — `winget install OpenJS.NodeJS.LTS` (the extension
itself needs no build step; Node only runs the classifier/demo server).

### 1. Start the classifier + demo server

```powershell
cd server
Copy-Item .env.example .env    # optional: put your key in .env
$env:AI_BASE_URL="https://api.openai.com/v1"   # or Groq / Gemini / OpenRouter
$env:AI_API_KEY="sk-..."                        # optional: no key = heuristic fallback
$env:AI_MODEL="gpt-4o-mini"
node classify.js
```

Server: <http://127.0.0.1:8787>
Demo page: <http://127.0.0.1:8787/demo/>

### 2. Load the extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Open <http://127.0.0.1:8787/demo/>
5. Click the extension icon to see the threat report

### 3. Verify

- The fake "Chrome is out of date" ad is hidden and reported as `malicious`
- The privacy-policy banner is briefly hidden, then **revealed** (AI says `legit`)
- The popup switch toggles protection: **off** reveals everything and sets an
  `OFF` toolbar badge; **on** rescans the page and hides threats again
- `http://127.0.0.1:8787/health` shows the active mode

---

## Architecture

```
 page DOM ──► heuristics.js      (candidate extraction, ~10ms)
            │
            ▼
        content.js              hide candidates immediately (no flash)
            │  PageScanRequest
            ▼
        background.js          observe redirect chains (webRequest)
            │  POST /classify
            ▼
        server/classify.js     IOC lookup → AI adjudication → fallback heuristics
            │  Verdict[]
            ▼
        content.js             block / warn / allow, attach reason
            │
            ▼
        popup.html             threat report (severity, indicators, reason)
```

**Fail-safe design:** every layer can fail. No AI key → heuristics. Server down →
background fallback. No verdict → element revealed. The demo never breaks.

---

## Repository map

```
extension/
  manifest.json        MV3 manifest (owned by Person A)
  heuristics.js        candidate extraction + scoring
  content.js           hide-first / reveal-on-verdict, MutationObserver
  background.js        redirect observation + classifier calls + fallback
  popup.html/.js/.css  threat report UI (owned by Person C)
  styles/inject.css    .aiadblock-hide
server/
  classify.js          HTTP server + model call + static demo host (Person B)
  sources.js           Google Safe Browsing IOC lookup
docs/
  CONTRACT.md          THE interface contract — read before coding
  DEMO.md              demo script + definition of done
demo/
  index.html           fake news page with malicious + benign ads
  phishing-mock.html   harmless phishing payload (never collects data)
```

---

## Team lanes

| Person | Owns | Do not touch |
| --- | --- | --- |
| **A — DOM/extension** | `manifest.json`, `heuristics.js`, `content.js`, `inject.css` | prompt/schema |
| **B — AI/security** | `classify.js`, `sources.js`, prompt, severity policy | manifest |
| **C — product/demo** | `popup.*`, `demo/*`, pitch, demo script | extraction logic |

---

## Roadmap

| Clock | Milestone |
| --- | --- |
| 0:00–0:45 | Contract agreed, extension loads, model returns valid JSON |
| 0:45–3:00 | **G1:** one ad hidden + one verdict shown end-to-end |
| 3:00–7:00 | **G2:** real pipeline, works on 3 real news sites |
| 7:00–11:00 | **G3:** IOC + heuristics + AI merged; malicious ad blocked |
| 11:00–15:00 | **G4:** UI polish, false-positive tuning, <500ms perceived |
| 15:00–19:00 | **G5:** full kill-chain demo runs 3× |
| 19:00–21:00 | Rehearse + record backup video |
| 21:00 | **FREEZE CODE** |

Cut order if behind: polish → IOC feeds → real-site support → UI → core block+explain loop.

---

## Environment variables

| Variable | Purpose |
| --- | --- |
| `AI_BASE_URL` | OpenAI-compatible endpoint (OpenAI, Groq, OpenRouter, Gemini compat) |
| `AI_API_KEY` | Model key. Unset = heuristic-only mode |
| `AI_MODEL` | Model id, e.g. `gpt-4o-mini`, `llama-3.1-8b-instant` |
| `SAFE_BROWSING_KEY` | Optional threat-intel overlay |
| `PORT` | Default `8787` |

Gemini compat base: `https://generativelanguage.googleapis.com/v1beta/openai`
Groq base: `https://api.groq.com/openai/v1`

---

## Privacy

When the AI classifier is enabled, the text snippet (up to 160 characters), tag,
classes, size, origin, and redirect chain of each ad-like element on a page are
sent to the model provider configured in `AI_BASE_URL`. Page HTML is never sent.
Do not use AI mode on pages containing sensitive information unless you have
reviewed that provider's data terms. Verdicts are cached in memory on the
classifier server only; nothing is written to disk.

## Scope and limitations

- **Network blocking:** a small bundled `declarativeNetRequest` ruleset
  (`extension/rules/ad-domains.json`) blocks 14 well-known ad and tracker domains.
  It is a starter list, not a full filter list.
- **Filter lists:** EasyList and uBlock syntax are not parsed.
- **Anti-adblock defusal:** not implemented.
- **Browsers:** Chrome only (Manifest V3).
- **Classifier server:** AI verdicts require the local Node server. Without it,
  the extension uses built-in rules only.

## Safety

The demo payload is a harmless local mock. It collects no data, downloads
nothing executable, and is never deployed. Do not point the demo at real
malware or third-party phishing infrastructure.
