import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

export const lookalikeUrlDetector: Detector = {
  id: 'url.lookalike_domain',
  category: 'domain',
  description: 'Links to domains imitating protected brands',
  run: ({ urls }) =>
    aggregateUrlIndicator(urls, ['lookalike', 'idn'], (m) => ({
      confidence: m.some((x) => x.severity === 'critical') ? 0.95 : 0.82,
      title: 'Link to a look-alike domain',
      description: `${m.length} link(s) point to domains built to resemble a well-known brand: ${[...new Set(m.map((x) => x.url.host))].slice(0, 3).join(', ')}.`,
      whyItMatters:
        'Look-alike domains host fake login pages that capture credentials while appearing to be the real service.',
      recommendation: 'Do not interact with the URL or enter credentials. Block the domain.',
      method:
        'Normalised link hosts (confusables, digit substitution, IDNA) and compared them with protected brand names via skeleton matching and Levenshtein distance.',
      attack: [ATTACK.spearphishingLink, ATTACK.masquerading],
    })),
};
