import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';

export const spfDetector: Detector = {
  id: 'auth.spf',
  category: 'authentication',
  description: 'SPF result recorded by the receiving server',
  run({ authentication }) {
    const spf = authentication.spf;
    if (spf.state !== 'fail') return [];
    const soft = spf.result === 'softfail';
    return [
      {
        severity: soft ? 'medium' : 'high',
        confidence: 0.95,
        title: soft ? 'SPF soft fail' : 'SPF authentication failed',
        description: `The receiving server recorded spf=${spf.result} for the envelope sender${spf.domain ? ` domain ${spf.domain}` : ''}.`,
        whyItMatters:
          'SPF lists the servers allowed to send for a domain. A failure means this message came from a server the domain owner did not authorise, which is typical of spoofed mail.',
        evidence: [
          { label: 'Result', value: spf.result ?? 'fail' },
          ...(spf.domain ? [{ label: 'Envelope domain', value: spf.domain }] : []),
          ...(authentication.source ? [{ label: 'Header', value: authentication.source }] : []),
        ],
        recommendation:
          'Treat the sender identity as unverified. Confirm through a known channel before acting on the message.',
        method:
          "Parsed the top-most Authentication-Results / Received-SPF header written by the recipient's mail server.",
        attack: [ATTACK.phishing],
        scoreGroup: 'authentication',
      },
    ];
  },
};
