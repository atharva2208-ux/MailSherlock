import type { Detector } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

export const suspiciousTldDetector: Detector = {
  id: 'url.suspicious_tld',
  category: 'url',
  description: 'Links on high-abuse top-level domains',
  run: ({ urls }) =>
    aggregateUrlIndicator(urls, ['suspicious_tld', 'deep_subdomains'], (m) => ({
      confidence: 0.6,
      severity: m.some((x) => x.severity === 'medium') ? 'medium' : 'low',
      title: 'Links to high-risk domains',
      description: `${m.length} link(s) use TLDs or subdomain structures disproportionately associated with abuse.`,
      whyItMatters:
        'Cheap, lightly-regulated TLDs and long subdomain chains are favoured for disposable phishing infrastructure. On their own they are weak evidence.',
      recommendation: 'Combine with other indicators before acting.',
      method:
        "Compared each host's public suffix (Public Suffix List) with a list of high-abuse TLDs and counted subdomain depth.",
    })),
};
