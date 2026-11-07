# Demo Script & Definition of Done

## The story (30 seconds)

> "Ads are one of the biggest malware delivery vectors on the web. Blocklists
> stop the ads we already know about. AI AdShield uses AI to stop the ones we
> don't — and tells you exactly why, before they run."

## The kill chain (90 seconds)

1. Open `http://127.0.0.1:8787/demo/` **with the extension enabled**.
2. Point at the fake **"Your Chrome is out of date"** ad — it never renders.
3. Click the extension icon:
   - `malicious`, severity `high`
   - indicators: brand impersonation, urgency lure, download trigger
   - reason readable in one line.
4. Point at the **privacy-policy banner** — it is visible. Say:
   "A naive blocker hides this because the class says `banner`. The AI said
   `legit` and revealed it. That's the false-positive problem, solved."
5. Show the **benign VPN ad** blocked as `benign_ad`.
6. Kill the classifier (`Ctrl+C` on the server) and reload:
   "Server down — heuristics still block the malicious ad. Fail-safe, not fail-open."
7. Optional: open `phishing-mock.html` directly and let the extension flag it.

## Comparison slide

| | uBlock Origin | AI AdShield |
| --- | --- | --- |
| Known ad domains | ✅ | ✅ (via heuristics) |
| Native / sponsored content | ⚠️ sometimes | ✅ with reason |
| Novel malvertising | ❌ | ✅ |
| Explains *why* | ❌ | ✅ severity + indicators |
| Fails open on API error | n/a | ✅ fails safe |

## Definition of done

- [ ] Malicious demo ad is blocked; 3+ indicators and a human-readable reason.
- [ ] Benign banner is ultimately revealed (proves no blunt hammer).
- [ ] Benign ad blocked and labeled `benign_ad`.
- [ ] API-down fallback still blocks the malicious ad.
- [ ] Perceived latency < 500 ms (hide is instant, verdict arrives async).
- [ ] Popup renders correctly on a 1280×800 projector.
- [ ] Three clean consecutive runs.
- [ ] Backup screen recording exists.
- [ ] Pitch deck has: problem, demo, architecture diagram, metrics, team.

## Metrics to claim (measure, don't invent)

- Detection rate on your labeled demo set (e.g. 9/10 malicious ads).
- False-positive rate on normal page content.
- Median verdict latency.
- % of candidates resolved by IOC vs heuristics vs AI.

## If the demo breaks on stage

1. Reload the page.
2. If the popup is empty, check `http://127.0.0.1:8787/health`.
3. Narrate the architecture while it recovers — judges grade understanding.
4. Last resort: play the backup recording.
