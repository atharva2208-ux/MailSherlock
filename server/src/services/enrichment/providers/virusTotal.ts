import type { ThreatIntelProvider } from './types.js';
import { getJson } from './types.js';

interface VtResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: Record<string, number>;
      reputation?: number;
      categories?: Record<string, string>;
    };
  };
}

export function virusTotalProvider(apiKey: string | undefined): ThreatIntelProvider {
  return {
    name: 'VirusTotal',
    description: 'Multi-engine reputation for domains and IP addresses',
    kinds: ['domain', 'ip'],
    configured: Boolean(apiKey),
    async lookup(kind, target, signal) {
      const path = kind === 'ip' ? 'ip_addresses' : 'domains';
      const body = (await getJson(
        `https://www.virustotal.com/api/v3/${path}/${encodeURIComponent(target)}`,
        {
          headers: { 'x-apikey': apiKey ?? '' },
          signal,
        },
      )) as VtResponse | null;
      const link = `https://www.virustotal.com/gui/${kind === 'ip' ? 'ip-address' : 'domain'}/${encodeURIComponent(target)}`;
      const stats = body?.data?.attributes?.last_analysis_stats;
      if (!stats)
        return {
          provider: 'VirusTotal',
          target,
          status: 'ok',
          verdict: 'unknown',
          summary: 'Not present in VirusTotal',
          link,
        };
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      return {
        provider: 'VirusTotal',
        target,
        status: 'ok',
        verdict: malicious >= 2 ? 'malicious' : malicious + suspicious > 0 ? 'suspicious' : 'clean',
        summary: `${malicious} of ${total} engines flag as malicious, ${suspicious} as suspicious`,
        details: {
          malicious,
          suspicious,
          harmless: stats.harmless ?? 0,
          undetected: stats.undetected ?? 0,
          reputation: body?.data?.attributes?.reputation ?? null,
        },
        link,
      };
    },
  };
}
