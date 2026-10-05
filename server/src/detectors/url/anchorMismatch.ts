import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

export const anchorMismatchDetector: Detector = {
  id: 'url.anchor_mismatch',
  category: 'url',
  description: 'Visible link text names a different domain than the link target',
  run: ({ urls }) =>
    aggregateUrlIndicator(urls, ['anchor_mismatch'], (m) => ({
      confidence: 0.93,
      title: 'Misleading link text',
      description: `${m.length} link(s) display one domain but navigate to another.`,
      whyItMatters:
        'The recipient checks the text they can see. Showing a trusted domain while linking elsewhere is deliberate deception.',
      recommendation: 'Hover links before clicking; treat the message as phishing.',
      method:
        "Compared the registrable domain shown in each anchor's text with the registrable domain of its href.",
      attack: [ATTACK.spearphishingLink],
    })),
};
