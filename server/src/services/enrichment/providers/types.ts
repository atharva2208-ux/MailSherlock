import type { ThreatIntelResult } from '../../../models/analysis.js';

export type TargetKind = 'domain' | 'ip' | 'url';

export interface ThreatIntelProvider {
  name: string;
  /** Human description of what the provider checks. */
  description: string;
  kinds: TargetKind[];
  configured: boolean;
  lookup(kind: TargetKind, target: string, signal: AbortSignal): Promise<ThreatIntelResult>;
}

export async function getJson(
  url: string,
  init: RequestInit & { signal: AbortSignal },
): Promise<unknown> {
  const response = await fetch(url, {
    ...init,
    headers: { accept: 'application/json', ...init.headers },
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}
