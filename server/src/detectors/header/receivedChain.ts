import type { Detector, DetectorFinding } from '../types.js';

export const receivedChainDetector: Detector = {
  id: 'header.received_chain',
  category: 'header',
  description: 'Anomalies in the Received routing chain',
  run({ received, metadata }) {
    const findings: DetectorFinding[] = [];
    const backwards = received.filter((hop) =>
      hop.flags.includes('timestamp earlier than previous hop'),
    );
    if (backwards.length) {
      findings.push({
        severity: 'medium',
        confidence: 0.7,
        title: 'Received chain timestamps go backwards',
        description: `${backwards.length} hop(s) are timestamped earlier than the hop before them by more than normal clock skew.`,
        whyItMatters:
          'Inconsistent hop times can indicate forged Received headers inserted to make the message look like it came through trusted servers.',
        evidence: backwards.slice(0, 4).map((hop) => ({
          label: `Hop ${hop.index}`,
          value: `${hop.by ?? '?'} at ${hop.timestamp} (${hop.delaySeconds}s)`,
        })),
        recommendation: 'Only trust hops added by your own mail infrastructure.',
        method:
          'Parsed each Received header, ordered hops chronologically and compared timestamps (5 minute skew tolerance).',
        scoreGroup: 'header',
      });
    }
    const origin = received[0];
    const noRdns = received.filter((hop) => hop.flags.includes('no reverse DNS for sending IP'));
    if (noRdns.length) {
      findings.push({
        severity: 'low',
        confidence: 0.6,
        title: 'Sending server has no reverse DNS',
        description: `The connecting server ${noRdns[0]!.fromIp} was recorded as "unknown" - it has no PTR record.`,
        whyItMatters:
          'Reputable mail servers almost always have reverse DNS. Missing PTR records are common for compromised hosts and throwaway VPS senders.',
        evidence: noRdns
          .slice(0, 3)
          .map((hop) => ({ label: `Hop ${hop.index}`, value: hop.from ?? '' })),
        recommendation: 'Check the sending IP against reputation services.',
        method: 'Looked for "unknown" host names alongside public IPs in Received headers.',
        scoreGroup: 'header',
      });
    }
    if (metadata.date && origin?.timestamp) {
      const drift = (Date.parse(metadata.date) - Date.parse(origin.timestamp)) / 1000;
      if (drift > 3600 || drift < -7 * 86400) {
        findings.push({
          severity: 'low',
          confidence: 0.6,
          title: 'Date header inconsistent with first relay',
          description:
            drift > 0
              ? `The Date header is ${Math.round(drift / 60)} minutes after the first server received the message.`
              : `The Date header is ${Math.round(-drift / 86400)} days before the first relay timestamp.`,
          whyItMatters:
            'Senders control the Date header. A large mismatch with relay timestamps suggests a forged or replayed message.',
          evidence: [
            { label: 'Date header', value: metadata.date },
            { label: 'First relay', value: origin.timestamp },
          ],
          recommendation: 'Use relay timestamps, not the Date header, for timeline reconstruction.',
          method: 'Compared the Date header with the earliest Received timestamp.',
          scoreGroup: 'header',
        });
      }
    }
    return findings;
  },
};
