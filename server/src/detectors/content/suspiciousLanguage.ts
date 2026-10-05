import type { Detector, DetectorFinding } from '../types.js';
import { intentFinding } from './intentFinding.js';

export const scamLureDetector: Detector = {
  id: 'content.scam_lure',
  category: 'content',
  description: 'Prize, delivery and employment scam lures',
  run(ctx) {
    const findings: DetectorFinding[] = [];
    const lures = [
      {
        id: 'prize_lure' as const,
        title: 'Prize or refund lure',
        why: 'Unexpected winnings or refunds that require a fee or personal details are advance-fee and data-harvesting scams.',
      },
      {
        id: 'delivery_lure' as const,
        title: 'Delivery problem lure',
        why: 'Fake delivery failures with small "fees" harvest card details; couriers do not collect fees through emailed links.',
      },
      {
        id: 'job_lure' as const,
        title: 'Employment scam lure',
        why: 'Unsolicited high-paying remote jobs that require a registration fee are a well-documented scam pattern.',
      },
    ];
    for (const lure of lures) {
      findings.push(
        ...intentFinding(ctx, {
          intents: [lure.id],
          thresholds: { medium: 2, low: 1 },
          spec: {
            title: lure.title,
            describe: () => 'The message uses a common scam storyline.',
            whyItMatters: lure.why,
            recommendation: "Check the claim through the organisation's official website or app.",
          },
        }),
      );
    }
    return findings;
  },
};
