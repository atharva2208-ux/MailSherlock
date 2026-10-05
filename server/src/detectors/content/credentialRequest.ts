import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';
import { intentFinding } from './intentFinding.js';

export const credentialRequestDetector: Detector = {
  id: 'content.credential_request',
  category: 'content',
  description: 'Requests for passwords, verification or MFA approval',
  run: (ctx) =>
    intentFinding(ctx, {
      intents: ['credential_request', 'mfa_request'],
      thresholds: { high: 4, medium: 2, low: 1 },
      spec: {
        title: ctx.content.intents.mfa_request
          ? 'Credential and MFA request'
          : 'Credential request',
        describe: (labels) =>
          `The message asks the recipient to sign in, verify or hand over authentication material (${labels.join(', ').toLowerCase()}).`,
        whyItMatters:
          'Stolen credentials and approved MFA prompts are the objective of most phishing. Real services ask you to sign in on their own site, not via an emailed link or form.',
        recommendation:
          'Do not provide credentials or approve prompts you did not initiate. Go to the service directly.',
        attack: ctx.content.intents.mfa_request
          ? [ATTACK.spearphishingLink, ATTACK.mfaFatigue]
          : [ATTACK.spearphishingLink],
      },
    }),
};
