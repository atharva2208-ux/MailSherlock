import { assessHomoglyph } from '../../services/analyzers/domain.js';
import type { Detector, DetectorFinding } from '../types.js';
import { ATTACK } from '../types.js';

export const homoglyphDetector: Detector = {
  id: 'impersonation.homoglyph',
  category: 'impersonation',
  description: 'Internationalised domains mixing scripts',
  run({ sender, urls }) {
    const findings: DetectorFinding[] = [];
    const hosts = new Map<string, string>();
    if (sender.domain) hosts.set(sender.domain, 'sender');
    for (const url of urls) if (url.host && !hosts.has(url.host)) hosts.set(url.host, 'link');

    for (const [host, role] of hosts) {
      const result = assessHomoglyph(host);
      if (!result?.mixedScript) continue;
      findings.push({
        severity: 'critical',
        confidence: 0.96,
        title: `Homoglyph ${role === 'sender' ? 'sender' : 'link'} domain`,
        description: `${host} renders as "${result.unicodeHost}", mixing ${result.scripts.join(' and ')} characters. It reads as "${result.skeleton}".`,
        whyItMatters:
          'Characters from other scripts can be pixel-identical to Latin letters, so the domain looks legitimate while pointing somewhere else entirely.',
        evidence: [
          { label: 'Encoded (punycode)', value: host },
          { label: 'Displayed as', value: result.unicodeHost },
          { label: 'Visual equivalent', value: result.skeleton },
          { label: 'Scripts', value: result.scripts.join(', ') },
        ],
        recommendation:
          'Block the domain. Configure mail clients/browsers to display punycode for mixed-script domains.',
        method:
          'Decoded IDNA punycode and checked each label for mixed Unicode scripts (UTS #39 confusables).',
        attack: [ATTACK.masquerading],
        scoreGroup: 'impersonation',
        relatedUrls:
          role === 'link'
            ? urls
                .filter((u) => u.host === host)
                .map((u) => u.url)
                .slice(0, 5)
            : undefined,
      });
    }
    return findings;
  },
};
