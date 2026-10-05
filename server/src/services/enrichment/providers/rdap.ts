import type { ThreatIntelProvider } from './types.js';
import { getJson } from './types.js';

interface RdapResponse {
  events?: { eventAction?: string; eventDate?: string }[];
  entities?: { roles?: string[]; vcardArray?: unknown[] }[];
  status?: string[];
}

const YOUNG_DOMAIN_DAYS = 30;

export function rdapProvider(enabled: boolean): ThreatIntelProvider {
  return {
    name: 'RDAP',
    description: 'Domain registration data (age, status) via the public RDAP bootstrap service',
    kinds: ['domain'],
    configured: enabled,
    async lookup(_kind, target, signal) {
      const body = (await getJson(`https://rdap.org/domain/${encodeURIComponent(target)}`, {
        signal,
      })) as RdapResponse | null;
      if (!body)
        return {
          provider: 'RDAP',
          target,
          status: 'ok',
          verdict: 'unknown',
          summary: 'No registration record found',
        };
      const registered = body.events?.find((e) => e.eventAction === 'registration')?.eventDate;
      const ageDays = registered
        ? Math.floor((Date.now() - Date.parse(registered)) / 86_400_000)
        : null;
      return {
        provider: 'RDAP',
        target,
        status: 'ok',
        verdict: ageDays !== null && ageDays < YOUNG_DOMAIN_DAYS ? 'suspicious' : 'unknown',
        summary:
          ageDays !== null
            ? `Registered ${ageDays} day(s) ago (${registered?.slice(0, 10)})`
            : 'Registration date not published',
        details: {
          registered: registered ?? null,
          ageDays,
          status: body.status?.join(', ') ?? null,
        },
      };
    },
  };
}
