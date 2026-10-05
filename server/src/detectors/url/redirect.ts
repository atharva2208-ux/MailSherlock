import type { Detector } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

export const redirectDetector: Detector = {
  id: 'url.redirect',
  category: 'url',
  description: 'Shorteners and redirect parameters',
  run: ({ urls }) =>
    aggregateUrlIndicator(urls, ['shortener', 'redirect'], (m) => ({
      confidence: 0.75,
      title: m.some((x) => x.label.includes('shortener'))
        ? 'URL shortener hides the destination'
        : 'Link redirects through another domain',
      description: `${m.length} link(s) do not reveal their final destination.`,
      whyItMatters:
        'Shorteners and open redirects on reputable domains are used to slip malicious destinations past filters and users.',
      recommendation: 'Expand the link with an isolated preview service rather than clicking it.',
      method:
        'Matched hosts against known shortener services and inspected redirect-style query parameters for embedded URLs.',
    })),
};
