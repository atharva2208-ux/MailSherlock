import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';

export const dmarcDetector: Detector = {
  id: 'auth.dmarc',
  category: 'authentication',
  description: 'DMARC result for the visible From domain',
  run({ authentication, sender }) {
    const dmarc = authentication.dmarc;
    if (dmarc.state === 'fail') {
      return [
        {
          severity: 'critical',
          confidence: 0.95,
          title: 'DMARC failed for the From domain',
          description: `The visible sender domain ${dmarc.domain ?? sender.domain ?? ''} is not authenticated by an aligned SPF or DKIM result.`,
          whyItMatters:
            'DMARC is what ties the address a recipient sees to an authenticated sending path. A failure means the From address is very likely spoofed.',
          evidence: [
            { label: 'Result', value: dmarc.result ?? 'fail' },
            { label: 'From domain', value: dmarc.domain ?? sender.domain ?? 'unknown' },
            {
              label: 'SPF / DKIM',
              value: `${authentication.spf.result ?? 'none'} / ${authentication.dkim.result ?? 'none'}`,
            },
          ],
          recommendation:
            'Treat as spoofed. Block or quarantine and report to the impersonated organisation if it is a known brand.',
          method: 'Parsed the dmarc= result in the top-most Authentication-Results header.',
          attack: [ATTACK.phishing, ATTACK.impersonation],
          scoreGroup: 'authentication',
        },
      ];
    }
    if (dmarc.state === 'not_present' && authentication.headerCount === 0 && sender.domain) {
      return [
        {
          severity: 'info',
          confidence: 1,
          title: 'No authentication results recorded',
          description:
            'The message carries no Authentication-Results header, so SPF, DKIM and DMARC outcomes cannot be assessed.',
          whyItMatters:
            'Without these results the sender identity cannot be verified from the message alone. This is normal for exported or forwarded copies that lost their receiving headers.',
          evidence: [{ label: 'Authentication-Results headers', value: '0' }],
          recommendation:
            'If possible, export the original message from the recipient mailbox including all headers.',
          method: 'Checked for Authentication-Results and Received-SPF headers.',
          scoreGroup: 'authentication',
        },
      ];
    }
    return [];
  },
};
