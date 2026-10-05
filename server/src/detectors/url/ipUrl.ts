import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

export const ipUrlDetector: Detector = {
  id: 'url.ip_host',
  category: 'url',
  description: 'Links to raw or obfuscated IP addresses',
  run: ({ urls }) =>
    aggregateUrlIndicator(urls, ['ip_host', 'obfuscated_ip'], (m) => ({
      confidence: 0.9,
      title: m.some((x) => x.label.includes('decimal'))
        ? 'Link to an obfuscated IP address'
        : 'Link to a raw IP address',
      description: `${m.length} link(s) point directly at an IP address instead of a domain name.`,
      whyItMatters:
        'Legitimate organisations link to their own domains. A bare IP hides who operates the server and avoids domain-reputation checks.',
      recommendation:
        'Do not open the link. Block the IP at the web proxy and check it against reputation services.',
      method:
        'Parsed each URL with a WHATWG URL parser and tested the host for IPv4/IPv6 and numeric encodings.',
      attack: [ATTACK.spearphishingLink],
    })),
};
