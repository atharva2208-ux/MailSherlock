import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';

const EXECUTIVE_TITLE =
  /\b(?:ceo|cfo|coo|cto|chief\s+\w+\s+officer|president|managing director|director|chairman|founder|vp)\b/i;

export const executiveImpersonationDetector: Detector = {
  id: 'impersonation.executive',
  category: 'impersonation',
  description: 'Executive identity combined with BEC behaviour',
  run({ sender, content, metadata, text }) {
    const titled =
      EXECUTIVE_TITLE.test(sender.displayName) || /sent from my (?:iphone|mobile)/i.test(text);
    const becAsk = ['payment_request', 'gift_card', 'bank_change'].some(
      (id) => content.intents[id as 'gift_card'],
    );
    const pressure = Boolean(content.intents.secrecy) || Boolean(content.intents.urgency);
    if (!titled || !becAsk || !pressure) return [];
    const replyElsewhere = metadata.replyTo?.some((r) => r.domain !== sender.domain);
    return [
      {
        severity: 'critical',
        confidence: sender.isFreeMail || replyElsewhere ? 0.9 : 0.75,
        title: 'Business email compromise pattern',
        description:
          'An executive persona asks for money or gift cards under time pressure and/or secrecy.',
        whyItMatters:
          'This combination - authority, a financial ask, urgency and a request to keep it quiet - is the signature of CEO fraud, which causes larger losses than any other email attack type.',
        evidence: [
          { label: 'Sender', value: `${sender.displayName} <${sender.address}>` },
          ...(sender.isFreeMail
            ? [{ label: 'Mailbox', value: 'Free-mail provider, not corporate' }]
            : []),
          ...(replyElsewhere
            ? [{ label: 'Reply-To', value: metadata.replyTo!.map((r) => r.address).join(', ') }]
            : []),
          {
            label: 'Requests',
            value: ['payment_request', 'gift_card', 'bank_change']
              .filter((id) => content.intents[id as 'gift_card'])
              .join(', ')
              .replace(/_/g, ' '),
          },
        ],
        recommendation:
          'Verify by phone using a number from the company directory. Never process payment changes or gift card requests received only by email.',
        method:
          'Correlated an executive title or mobile signature with financial-request, urgency and secrecy intents.',
        attack: [ATTACK.impersonation],
        scoreGroup: 'impersonation',
      },
    ];
  },
};
