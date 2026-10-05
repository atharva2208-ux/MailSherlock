import type { ThreatIntelProvider } from './types.js';

export function safeBrowsingProvider(apiKey: string | undefined): ThreatIntelProvider {
  return {
    name: 'Google Safe Browsing',
    description: "Google's list of known phishing and malware URLs",
    kinds: ['url', 'domain'],
    configured: Boolean(apiKey),
    async lookup(kind, target, signal) {
      const url = kind === 'domain' ? `http://${target}/` : target;
      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey ?? '')}`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'mailsherlock', clientVersion: '1.0.0' },
            threatInfo: {
              threatTypes: [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION',
              ],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url }],
            },
          }),
          signal,
        },
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { matches?: { threatType: string }[] };
      const matches = body.matches ?? [];
      return {
        provider: 'Google Safe Browsing',
        target,
        status: 'ok',
        verdict: matches.length ? 'malicious' : 'clean',
        summary: matches.length
          ? `Listed as ${[...new Set(matches.map((m) => m.threatType))].join(', ')}`
          : 'Not on Safe Browsing lists',
      };
    },
  };
}
