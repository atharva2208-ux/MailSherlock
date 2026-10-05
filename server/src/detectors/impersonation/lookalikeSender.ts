import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';

export const lookalikeSenderDetector: Detector = {
  id: 'impersonation.lookalike_sender',
  category: 'domain',
  description: 'Sender domain imitates a protected brand',
  run({ sender }) {
    const match = sender.lookalike;
    if (!match || !sender.domain) return [];
    return [
      {
        severity: match.confidence >= 0.9 ? 'critical' : 'high',
        confidence: match.confidence,
        title: 'Look-alike sender domain',
        description: match.detail,
        whyItMatters: `Look-alike domains are registered specifically to pass a quick visual check. ${match.brand.name} does not send from ${sender.domain}.`,
        evidence: [
          { label: 'Sender domain', value: sender.domain },
          { label: 'Imitated brand', value: match.brand.name },
          { label: 'Technique', value: match.technique.replace(/_/g, ' ') },
          { label: 'Official domains', value: match.brand.domains.slice(0, 5).join(', ') },
        ],
        recommendation: 'Block the domain and search mail logs for other messages from it.',
        method:
          'Normalised the domain (Unicode confusables, digit substitution) and compared it to protected brand names using exact skeleton matching and Levenshtein distance.',
        attack: [ATTACK.impersonation, ATTACK.masquerading],
        scoreGroup: 'impersonation',
      },
    ];
  },
};
