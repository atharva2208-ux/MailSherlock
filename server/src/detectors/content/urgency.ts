import type { Detector } from '../types.js';
import { intentFinding } from './intentFinding.js';

export const urgencyDetector: Detector = {
  id: 'content.urgency',
  category: 'content',
  description: 'Time pressure designed to short-circuit careful checking',
  run: (ctx) =>
    intentFinding(ctx, {
      intents: ['urgency'],
      thresholds: { medium: 3, low: 1.5, info: 0.6 },
      spec: {
        title: 'Urgency language',
        describe: () => 'The message imposes deadlines or demands immediate action.',
        whyItMatters:
          'Artificial deadlines push recipients to act before they verify. On its own urgency is common in marketing; it matters when paired with a request.',
        recommendation:
          'Slow down: legitimate organisations give reasonable time and alternative channels.',
      },
    }),
};
