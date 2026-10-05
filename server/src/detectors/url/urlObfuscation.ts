import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

export const urlObfuscationDetector: Detector = {
  id: 'url.obfuscation',
  category: 'url',
  description: 'URL tricks that disguise the real destination',
  run: ({ urls }) =>
    aggregateUrlIndicator(urls, ['userinfo', 'encoded', 'dangerous_scheme'], (m) => ({
      confidence: 0.92,
      title: m.some((x) => x.label.includes('@'))
        ? 'URL uses "@" to disguise its destination'
        : 'Obfuscated URL',
      description: m.some((x) => x.label.includes('@'))
        ? 'Text before "@" in a URL is a username, not the host. Browsers connect to whatever follows the "@".'
        : 'The URL is encoded or uses a scheme that hides what it does.',
      whyItMatters:
        'Obfuscation exists to fool a human glance or a naive filter. Benign senders have no reason to hide where a link goes.',
      recommendation: 'Do not open the link. Extract the real host for blocking.',
      method:
        'Inspected the URL authority for userinfo, percent-encoding and executable schemes (javascript:, data:text/html).',
      attack: [ATTACK.spearphishingLink],
    })),
};
