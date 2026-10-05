import type { ThreatIntelProvider } from './types.js';
import { getJson } from './types.js';

interface SearchResponse {
  total?: number;
  results?: {
    task?: { time?: string };
    result?: string;
    verdicts?: { overall?: { malicious?: boolean } };
  }[];
}

/**
 * Uses urlscan.io *search* only. Submitting a scan would make urlscan visit the
 * attacker's URL on our behalf, which MailSherlock never does automatically.
 */
export function urlScanProvider(apiKey: string | undefined): ThreatIntelProvider {
  return {
    name: 'URLScan',
    description: 'Existing public scans of a domain (search only, never submits)',
    kinds: ['domain'],
    configured: Boolean(apiKey),
    async lookup(_kind, target, signal) {
      const body = (await getJson(
        `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${target}`)}&size=10`,
        {
          headers: { 'API-Key': apiKey ?? '' },
          signal,
        },
      )) as SearchResponse | null;
      const results = body?.results ?? [];
      const malicious = results.filter((r) => r.verdicts?.overall?.malicious).length;
      return {
        provider: 'URLScan',
        target,
        status: 'ok',
        verdict: malicious ? 'malicious' : results.length ? 'unknown' : 'unknown',
        summary: results.length
          ? `${body?.total ?? results.length} historical scan(s); ${malicious} with a malicious verdict`
          : 'No existing scans',
        details: {
          scans: body?.total ?? 0,
          maliciousVerdicts: malicious,
          latest: results[0]?.task?.time ?? null,
        },
        link: `https://urlscan.io/search/#domain:${encodeURIComponent(target)}`,
      };
    },
  };
}
