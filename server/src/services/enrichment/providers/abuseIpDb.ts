import type { ThreatIntelProvider } from './types.js';
import { getJson } from './types.js';

interface AbuseResponse {
  data?: {
    abuseConfidenceScore?: number;
    totalReports?: number;
    countryCode?: string;
    isp?: string;
    usageType?: string;
  };
}

export function abuseIpDbProvider(apiKey: string | undefined): ThreatIntelProvider {
  return {
    name: 'AbuseIPDB',
    description: 'Community abuse reports for IP addresses',
    kinds: ['ip'],
    configured: Boolean(apiKey),
    async lookup(_kind, target, signal) {
      const body = (await getJson(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(target)}&maxAgeInDays=90`,
        { headers: { Key: apiKey ?? '' }, signal },
      )) as AbuseResponse | null;
      const score = body?.data?.abuseConfidenceScore ?? 0;
      return {
        provider: 'AbuseIPDB',
        target,
        status: 'ok',
        verdict: score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : 'clean',
        summary: `Abuse confidence ${score}% from ${body?.data?.totalReports ?? 0} report(s) in 90 days`,
        details: {
          abuseConfidenceScore: score,
          totalReports: body?.data?.totalReports ?? 0,
          country: body?.data?.countryCode ?? null,
          isp: body?.data?.isp ?? null,
        },
        link: `https://www.abuseipdb.com/check/${encodeURIComponent(target)}`,
      };
    },
  };
}
