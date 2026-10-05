import { orgDomain } from '../../services/parser/headers.js';
import { FREE_MAIL_DOMAINS } from '../../services/analyzers/domain.js';
import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';

export const replyToMismatchDetector: Detector = {
  id: 'header.reply_to_mismatch',
  category: 'sender',
  description: 'Reply-To points to a different organisation than From',
  run({ metadata, sender }) {
    const replyTo = metadata.replyTo?.[0];
    if (!replyTo?.domain || !sender.orgDomain) return [];
    const replyOrg = orgDomain(replyTo.domain);
    if (replyOrg === sender.orgDomain) return [];
    const toFreeMail = FREE_MAIL_DOMAINS.has(replyOrg);
    return [
      {
        severity: toFreeMail || sender.lookalike ? 'high' : 'medium',
        confidence: 0.85,
        title: toFreeMail
          ? 'Replies diverted to a free-mail account'
          : 'Reply-To differs from sender organisation',
        description: `Replies to this message go to ${replyTo.address}, not to the sender's domain ${sender.domain}.`,
        whyItMatters:
          "Diverting replies lets an attacker spoof or borrow a trusted sender identity while still receiving the victim's response - the core mechanic of business email compromise.",
        evidence: [
          { label: 'From', value: sender.address ?? '' },
          { label: 'Reply-To', value: replyTo.address },
        ],
        recommendation:
          'Do not reply directly. Contact the sender using an address or phone number you already know.',
        method: 'Compared the organisational (PSL registrable) domains of From and Reply-To.',
        attack: [ATTACK.phishing],
        scoreGroup: 'sender',
      },
    ];
  },
};
