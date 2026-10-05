import type { Finding, Severity } from '../../models/analysis.js';
import { brandForOfficialDomain } from '../analyzers/brands.js';
import type { DetectionContext } from '../../detectors/types.js';

const DOWNGRADE: Record<Severity, Severity> = {
  critical: 'medium',
  high: 'low',
  medium: 'info',
  low: 'info',
  info: 'info',
};
/** Content findings that stay meaningful even from an authenticated sender. */
const NEVER_DOWNGRADE = new Set(['content.financial_request', 'content.hidden_text']);

export interface TrustContext {
  trusted: boolean;
  reasons: string[];
  blockers: string[];
}

/**
 * Decide whether the message comes from an authenticated sender whose links
 * stay within its own organisation. This is the main false-positive control:
 * a real password reset and a phishing "password reset" use the same words,
 * but only one is DMARC-aligned and links back to the sending domain.
 */
export function assessTrust(ctx: DetectionContext, findings: Finding[]): TrustContext {
  const reasons: string[] = [];
  const blockers: string[] = [];
  const { dmarc } = ctx.authentication;

  if (dmarc.state === 'pass' && dmarc.aligned !== false)
    reasons.push(`DMARC pass for ${dmarc.domain ?? ctx.sender.domain}`);
  else blockers.push('sender domain not authenticated by DMARC');

  if (ctx.sender.lookalike) blockers.push('sender domain imitates a brand');
  if (
    findings.some(
      (f) =>
        f.detector === 'impersonation.homoglyph' || f.detector === 'impersonation.display_name',
    )
  ) {
    blockers.push('display name or domain impersonation');
  }

  const senderBrand = ctx.sender.orgDomain
    ? brandForOfficialDomain(ctx.sender.orgDomain)
    : undefined;
  const foreign = ctx.urls
    .filter((u) => u.source !== 'image' && u.registrableDomain)
    .filter(
      (u) =>
        u.registrableDomain !== ctx.sender.orgDomain &&
        (!senderBrand || brandForOfficialDomain(u.registrableDomain) !== senderBrand),
    );
  if (foreign.length)
    blockers.push(
      `${foreign.length} link(s) leave the sender's domain (${[...new Set(foreign.map((u) => u.registrableDomain))].slice(0, 3).join(', ')})`,
    );
  else if (ctx.urls.length) reasons.push("all links stay on the sender's own domain");

  if (ctx.urls.some((u) => u.risk === 'critical' || u.risk === 'high'))
    blockers.push('high-risk link indicators');
  if (ctx.attachments.some((a) => a.risk === 'critical' || a.risk === 'high'))
    blockers.push('dangerous attachment');
  if (ctx.message.htmlInspection?.forms.some((f) => f.hasPasswordField))
    blockers.push('embedded password form');

  return { trusted: blockers.length === 0 && reasons.length > 0, reasons, blockers };
}

export function applyTrustAdjustments(findings: Finding[], trust: TrustContext): Finding[] {
  if (!trust.trusted) return findings;
  const reason = `Sender is authenticated and links stay on its own domain (${trust.reasons.join('; ')}); this language is expected in genuine transactional mail.`;
  return findings.map((finding) => {
    if (finding.category !== 'content' || NEVER_DOWNGRADE.has(finding.detector)) return finding;
    const to = DOWNGRADE[finding.severity];
    if (to === finding.severity) return finding;
    return { ...finding, severity: to, adjustment: { from: finding.severity, to, reason } };
  });
}
