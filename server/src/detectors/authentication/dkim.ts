import type { Detector } from '../types.js';

export const dkimDetector: Detector = {
  id: 'auth.dkim',
  category: 'authentication',
  description: 'DKIM verification result',
  run({ authentication }) {
    const dkim = authentication.dkim;
    if (dkim.state !== 'fail') return [];
    return [
      {
        severity: 'high',
        confidence: 0.9,
        title: 'DKIM signature failed verification',
        description: `The receiving server recorded dkim=${dkim.result}${dkim.domain ? ` for signing domain ${dkim.domain}` : ''}.`,
        whyItMatters:
          'A DKIM signature that does not verify means the message was altered after signing or the signature was forged. Legitimate bulk senders almost always sign correctly.',
        evidence: [
          { label: 'Result', value: dkim.result ?? 'fail' },
          ...(dkim.domain ? [{ label: 'Signing domain (d=)', value: dkim.domain }] : []),
        ],
        recommendation: 'Do not trust the content as originating from the claimed organisation.',
        method: 'Parsed the dkim= result in the top-most Authentication-Results header.',
        scoreGroup: 'authentication',
      },
    ];
  },
};
