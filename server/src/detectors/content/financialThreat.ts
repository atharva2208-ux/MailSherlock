import type { Detector } from '../types.js';
import { intentFinding } from './intentFinding.js';

export const financialRequestDetector: Detector = {
  id: 'content.financial_request',
  category: 'content',
  description: 'Payment, bank-detail change and gift-card requests',
  run: (ctx) =>
    intentFinding(ctx, {
      intents: ['payment_request', 'bank_change', 'gift_card'],
      thresholds: { high: 3.5, medium: 2, low: 1 },
      spec: {
        title: ctx.content.intents.bank_change
          ? 'Request to pay to changed bank details'
          : ctx.content.intents.gift_card
            ? 'Gift card request'
            : 'Payment request',
        describe: (labels) =>
          `The message asks for money to be moved (${labels.join(', ').toLowerCase()}).`,
        whyItMatters:
          'Invoice fraud and gift-card scams convert directly into irrecoverable losses. Changed bank details are the single most reliable marker of invoice fraud.',
        recommendation:
          'Verify any payment request or bank change by phone using contact details already on file, never those in the email.',
      },
    }),
};
