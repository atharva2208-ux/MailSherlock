import { BRAND_MENTION_PATTERNS, brandForOfficialDomain } from '../../services/analyzers/brands.js';
import { orgDomain } from '../../services/parser/headers.js';
import type { Detector, DetectorFinding } from '../types.js';
import { ATTACK } from '../types.js';

const EMAIL_IN_NAME = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/;

export const displayNameSpoofingDetector: Detector = {
  id: 'impersonation.display_name',
  category: 'impersonation',
  description: 'Display name claims an identity the sending address does not support',
  run({ sender, authentication }) {
    const findings: DetectorFinding[] = [];
    const name = sender.displayName;
    if (!name || !sender.domain || !sender.orgDomain) return findings;

    const embedded = EMAIL_IN_NAME.exec(name);
    if (embedded && orgDomain(embedded[1]!.toLowerCase()) !== sender.orgDomain) {
      findings.push({
        severity: 'high',
        confidence: 0.9,
        title: 'Display name contains a different email address',
        description: `The display name shows "${embedded[0]}" but the message was sent from ${sender.address}.`,
        whyItMatters:
          'Many clients show only the display name, so an address inside it is what the recipient believes they are talking to.',
        evidence: [
          { label: 'Display name', value: name },
          { label: 'Actual address', value: sender.address ?? '' },
        ],
        recommendation:
          'Expand the sender details in your mail client before trusting the message.',
        method:
          'Extracted addresses from the From display name and compared organisational domains.',
        attack: [ATTACK.impersonation],
        scoreGroup: 'impersonation',
      });
    }

    const officialBrand = brandForOfficialDomain(sender.orgDomain);
    for (const { brand, pattern } of BRAND_MENTION_PATTERNS) {
      if (!pattern.test(name) || officialBrand === brand) continue;
      const authenticatedLookalike = authentication.dmarc.state === 'pass' && sender.lookalike;
      findings.push({
        severity: sender.lookalike || authentication.dmarc.state === 'fail' ? 'critical' : 'high',
        confidence: sender.lookalike ? 0.95 : 0.85,
        title: `Display name impersonates ${brand.name}`,
        description: `The sender calls itself "${name}" but sends from ${sender.domain}, which is not a ${brand.name} domain.`,
        whyItMatters: `Recipients trust the familiar ${brand.name} name. ${brand.name} sends from ${brand.domains.slice(0, 3).join(', ')}${brand.domains.length > 3 ? ', …' : ''}.${authenticatedLookalike ? ' Authentication passing only proves the attacker controls the look-alike domain.' : ''}`,
        evidence: [
          { label: 'Display name', value: name },
          { label: 'Sending domain', value: sender.domain },
          { label: 'Official domains', value: brand.domains.slice(0, 5).join(', ') },
        ],
        recommendation: `Do not interact. Report it to ${brand.name}'s abuse/phishing address.`,
        method:
          'Matched brand names in the display name against the brand registry and compared with the sending organisational domain.',
        attack: [ATTACK.impersonation],
        scoreGroup: 'impersonation',
      });
      break;
    }
    return findings;
  },
};
