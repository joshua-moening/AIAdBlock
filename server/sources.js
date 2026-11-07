/* Google Safe Browsing IOC overlay.
 * Free key: https://developers.google.com/safe-browsing/v4/get-started
 * OWNER: Person B.
 */

const ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/**
 * @param {string[]} urls
 * @returns {Promise<Map<string, string>>} url -> threatType
 */
export async function lookupSafeBrowsing(urls) {
  const key = process.env.SAFE_BROWSING_KEY;
  if (!key || !urls.length) return new Map();

  try {
    const response = await fetch(`${ENDPOINT}?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'apollo-adshield-hackathon', clientVersion: '0.1.0' },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [...new Set(urls)].slice(0, 50).map((url) => ({ url })),
        },
      }),
    });

    if (!response.ok) {
      console.warn('[sources] Safe Browsing returned', response.status);
      return new Map();
    }

    const data = await response.json();
    const hits = new Map();
    for (const match of data.matches || []) {
      if (match.threat?.url) hits.set(match.threat.url, match.threatType);
    }
    return hits;
  } catch (error) {
    console.warn('[sources] Safe Browsing failed:', error.message);
    return new Map();
  }
}
