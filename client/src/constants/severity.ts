import type { Classification, RiskLevel, Severity } from '../types';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const RISK_LABEL: Record<RiskLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  safe: 'Safe',
};

export const CLASSIFICATION_LABEL: Record<Classification, string> = {
  phishing: 'Phishing',
  suspicious: 'Suspicious',
  legitimate: 'Legitimate',
};

/** CSS variable for each level; the same mapping is used everywhere. */
export const LEVEL_COLOR: Record<Severity | RiskLevel | 'none', string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  safe: 'var(--safe)',
  info: 'var(--info)',
  none: 'var(--faint)',
};

export const CLASSIFICATION_COLOR: Record<Classification, string> = {
  phishing: 'var(--critical)',
  suspicious: 'var(--medium)',
  legitimate: 'var(--safe)',
};

/** Score bands, mirroring server/src/services/scoring/riskScore.ts. */
export const RISK_BANDS: { level: RiskLevel; from: number; to: number }[] = [
  { level: 'safe', from: 0, to: 20 },
  { level: 'low', from: 20, to: 40 },
  { level: 'medium', from: 40, to: 60 },
  { level: 'high', from: 60, to: 80 },
  { level: 'critical', from: 80, to: 100 },
];

export const CATEGORY_LABEL: Record<string, string> = {
  authentication: 'Authentication',
  header: 'Header forensics',
  sender: 'Sender consistency',
  impersonation: 'Impersonation',
  domain: 'Domain',
  url: 'Links',
  content: 'Content',
  attachment: 'Attachments',
  threat_intel: 'Threat intel',
};

export const FEEDBACK_LABEL: Record<string, string> = {
  confirmed_phishing: 'Confirmed phishing',
  confirmed_legitimate: 'Confirmed legitimate',
  false_positive: 'False positive',
  false_negative: 'False negative',
  uncertain: 'Uncertain',
};

/** Mirrors GROUP_LABELS in the server scoring engine; links findings to score contributions. */
export const SCORE_GROUP_LABEL: Record<string, string> = {
  authentication: 'Sender authentication',
  sender: 'Sender consistency',
  header: 'Header forensics',
  impersonation: 'Impersonation',
  url: 'Link analysis',
  credential_form: 'Credential collection',
  content: 'Social-engineering language',
  content_pattern: 'Phishing pressure pattern',
  content_hidden: 'Hidden content',
  attachment: 'Attachments',
  threat_intel: 'Threat intelligence',
};
