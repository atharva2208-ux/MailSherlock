import type { Detector } from '../types.js';
import type { DetectorFinding } from '../types.js';
import { intentFinding } from './intentFinding.js';

export const socialEngineeringDetector: Detector = {
  id: 'content.social_engineering',
  category: 'content',
  description: 'Threats, secrecy and authority pressure',
  run(ctx) {
    const findings: DetectorFinding[] = [];
    findings.push(
      ...intentFinding(ctx, {
        intents: ['account_threat'],
        thresholds: { medium: 3, low: 1.5, info: 1 },
        spec: {
          title: 'Threat of account loss',
          describe: () =>
            'The message threatens suspension, closure or loss of access, or reports unusual activity.',
          whyItMatters:
            "Fear of losing access is the most common pretext for credential phishing. Legitimate alerts exist too, which is why this is weighed together with the sender's authenticity.",
          recommendation: 'Check your account status by visiting the service directly.',
        },
      }),
    );
    findings.push(
      ...intentFinding(ctx, {
        intents: ['secrecy', 'authority'],
        thresholds: { high: 4, medium: 2, low: 1 },
        spec: {
          title: 'Secrecy and authority pressure',
          describe: (labels) =>
            `The message leans on authority or asks the recipient to keep the request quiet (${labels.join(', ').toLowerCase()}).`,
          whyItMatters:
            'Isolating the target from colleagues prevents the one conversation that would expose the fraud.',
          recommendation:
            'Escalate unusual requests to a manager or security team regardless of who appears to have sent them.',
        },
      }),
    );

    const { intents, callToAction } = ctx.content;
    const pressure = (intents.urgency?.score ?? 0) + (intents.account_threat?.score ?? 0);
    const ask = [
      'credential_request',
      'mfa_request',
      'payment_request',
      'bank_change',
      'gift_card',
    ].filter((id) => intents[id as 'gift_card']);
    if (pressure >= 2 && ask.length && (callToAction || intents.gift_card || intents.bank_change)) {
      findings.push({
        severity: 'high',
        confidence: 0.85,
        title: 'Pressure + request + action pattern',
        description: `Time pressure or threats are combined with a request (${ask.join(', ').replace(/_/g, ' ')}) and a way to act on it immediately.`,
        whyItMatters:
          'Individually these elements appear in normal mail. Together they form the standard phishing script: create fear, make a demand, provide the means.',
        evidence: [
          { label: 'Pressure score', value: pressure.toFixed(2) },
          { label: 'Requests', value: ask.join(', ').replace(/_/g, ' ') },
          {
            label: 'Call to action',
            value: callToAction ? 'links or form present' : 'reply requested',
          },
        ],
        recommendation: 'Treat as phishing unless the sender is independently verified.',
        method:
          'Correlated urgency/threat intents with request intents and the presence of links or forms.',
        scoreGroup: 'content_pattern',
        spans: [...(intents.urgency?.spans ?? []), ...(intents.account_threat?.spans ?? [])].sort(
          (a, b) => a.start - b.start,
        ),
      });
    }
    return findings;
  },
};
