import { orgDomain } from '../../services/parser/headers.js';
import type { Detector, DetectorFinding } from '../types.js';
import { ATTACK } from '../types.js';
import { aggregateUrlIndicator } from './shared.js';

function actionHost(action: string): string | null {
  if (!/^https?:/i.test(action)) return null;
  try {
    return new URL(action).hostname;
  } catch {
    return null;
  }
}

export const credentialHarvestingDetector: Detector = {
  id: 'url.credential_harvesting',
  category: 'url',
  description: 'Credential-collection forms and login-style landing pages',
  run({ urls, message, sender }) {
    const findings: DetectorFinding[] = [];
    const forms = message.htmlInspection?.forms ?? [];
    const passwordForms = forms.filter((f) => f.hasPasswordField);
    if (passwordForms.length || forms.some((f) => f.action)) {
      const external = forms.filter((f) => {
        const host = actionHost(f.action);
        return host !== null && (!sender.orgDomain || orgDomain(host) !== sender.orgDomain);
      });
      findings.push({
        severity: passwordForms.length ? 'critical' : external.length ? 'high' : 'medium',
        confidence: passwordForms.length ? 0.97 : 0.8,
        title: passwordForms.length
          ? 'Password form embedded in the email'
          : 'Data-collection form embedded in the email',
        description: `${forms.length} HTML form(s)${passwordForms.length ? `, ${passwordForms.length} with a password field,` : ''} submit${forms.length === 1 ? 's' : ''} to ${forms
          .map((f) => f.action || '(no action)')
          .slice(0, 2)
          .join(', ')}.`,
        whyItMatters:
          'Legitimate services never collect passwords inside an email. Whatever is typed is posted straight to the attacker.',
        evidence: forms.slice(0, 4).map((f, i) => ({
          label: `Form ${i + 1}`,
          value: `${f.method.toUpperCase()} ${f.action || '(none)'} - fields: ${f.inputNames.join(', ') || 'unnamed'}`,
        })),
        recommendation:
          'Do not submit anything. If credentials were entered, reset the password and revoke sessions immediately.',
        method:
          'Parsed the HTML body for <form> elements, password inputs and their submission targets.',
        attack: [ATTACK.spearphishingLink],
        scoreGroup: 'credential_form',
        relatedUrls: forms
          .map((f) => f.action)
          .filter(Boolean)
          .slice(0, 5),
      });
    }
    findings.push(
      ...aggregateUrlIndicator(urls, ['credential_path', 'insecure_credential'], (m) => ({
        confidence: 0.6,
        severity: 'medium',
        title: 'Login-style landing page on a non-brand domain',
        description: `${m.length} link(s) lead to sign-in, verification or account paths on domains that do not belong to a known service.`,
        whyItMatters:
          'Credential phishing kits mimic the URL structure of real login flows (/login, /verify, /account).',
        recommendation: 'Navigate to the service directly rather than through the link.',
        method:
          'Matched decoded URL paths against login/verification patterns, excluding official brand domains.',
        attack: [ATTACK.spearphishingLink],
      })),
    );
    return findings;
  },
};
