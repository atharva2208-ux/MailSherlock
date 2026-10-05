import type {
  Classification,
  Finding,
  MlAssessment,
  RiskAssessment,
  RiskLevel,
  ScoreContribution,
  Severity,
} from '../../models/analysis.js';
import type { TrustContext } from './correlation.js';

export const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 35,
  high: 22,
  medium: 10,
  low: 4,
  info: 0,
};

/**
 * Upper bound per evidence group. Findings in one group describe correlated
 * evidence (e.g. SPF and DMARC failing for the same reason), so a group can
 * only contribute so much no matter how many findings it contains.
 */
export const GROUP_CAPS: Record<string, number> = {
  authentication: 40,
  sender: 25,
  header: 12,
  impersonation: 45,
  url: 40,
  credential_form: 40,
  content: 25,
  content_pattern: 15,
  content_hidden: 12,
  attachment: 50,
  threat_intel: 45,
};

const GROUP_LABELS: Record<string, string> = {
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

/** ML may corroborate rule evidence but may not raise a verdict on its own. */
export const ML_MAX_POINTS = 20;
export const ML_SOLO_CAP = 8;
const ML_SOLO_RULE_THRESHOLD = 10;
const CRITICAL_FLOOR = 60;
/**
 * Raw evidence points are unbounded (a message can trip many groups), so they
 * are mapped onto 0-100 with a saturating curve rather than clamped. Clamping
 * makes every heavily-evidenced message score 100; the curve keeps ordering
 * (more independent evidence => higher score) while approaching 100.
 * raw 20 -> 28, 40 -> 49, 60 -> 63, 100 -> 81, 150 -> 92.
 */
export const SATURATION_SCALE = 60;

export function normaliseScore(raw: number): number {
  return raw <= 0 ? 0 : 100 * (1 - Math.exp(-raw / SATURATION_SCALE));
}

export function levelFor(score: number): RiskLevel {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'safe';
}

export function classificationFor(score: number): Classification {
  if (score >= 60) return 'phishing';
  if (score >= 35) return 'suspicious';
  return 'legitimate';
}

function groupScore(findings: Finding[], cap: number): number {
  const points = findings
    .map((f) => SEVERITY_POINTS[f.severity] * f.confidence)
    .filter((p) => p > 0)
    .sort((a, b) => b - a);
  // Diminishing returns: each additional finding in a group counts half as much as the previous one.
  const total = points.reduce((sum, value, rank) => sum + value * 0.5 ** rank, 0);
  return Math.min(cap, total);
}

const round = (value: number) => Math.round(value * 10) / 10;

export function scoreRisk(
  findings: Finding[],
  ml: MlAssessment,
  trust: TrustContext,
): RiskAssessment {
  const contributions: ScoreContribution[] = [];
  const groups = new Map<string, Finding[]>();
  for (const finding of findings)
    groups.set(finding.scoreGroup, [...(groups.get(finding.scoreGroup) ?? []), finding]);

  let ruleScore = 0;
  for (const [group, members] of groups) {
    const points = groupScore(members, GROUP_CAPS[group] ?? 20);
    if (points <= 0) continue;
    ruleScore += points;
    contributions.push({
      label: GROUP_LABELS[group] ?? group,
      points: round(points),
      kind: 'rule',
      detail: `${members.length} finding(s); capped at ${GROUP_CAPS[group] ?? 20}`,
    });
  }
  ruleScore = Math.min(100, ruleScore);
  let score = ruleScore;

  const highCategories = new Set(
    findings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .map((f) => f.category),
  );
  if (highCategories.size >= 3) {
    const bonus = highCategories.size >= 4 ? 12 : 8;
    score += bonus;
    contributions.push({
      label: 'Independent evidence corroborates',
      points: bonus,
      kind: 'correlation',
      detail: `High-severity evidence in ${highCategories.size} separate categories: ${[...highCategories].join(', ')}`,
    });
  }

  if (ml.available && ml.probability !== undefined && ml.threshold !== undefined) {
    const p = ml.probability;
    const t = ml.threshold;
    let points = 0;
    let detail = '';
    if (p >= t) {
      points = 6 + (ML_MAX_POINTS - 6) * ((p - t) / Math.max(1e-6, 1 - t));
      detail = `Classifier probability ${(p * 100).toFixed(1)}% is above its ${(t * 100).toFixed(1)}% threshold`;
      if (ml.confidence === 'low') {
        points *= 0.5;
        detail += '; halved for low model confidence';
      }
      if (ruleScore < ML_SOLO_RULE_THRESHOLD) {
        points = Math.min(points, ML_SOLO_CAP);
        detail += `; capped at ${ML_SOLO_CAP} because no rule evidence corroborates it`;
      }
      if (trust.trusted) {
        points *= 0.25;
        detail += '; reduced because the sender is authenticated and links stay on its domain';
      }
    } else if (!findings.some((f) => f.severity === 'critical')) {
      points = -8 * ((t - p) / Math.max(1e-6, t));
      detail = `Classifier probability ${(p * 100).toFixed(1)}% is below its threshold`;
    }
    if (Math.abs(points) >= 0.1) {
      score += points;
      contributions.push({
        label: 'Machine-learning assessment',
        points: round(points),
        kind: 'ml',
        detail,
      });
    }
  }

  if (trust.trusted) {
    contributions.push({
      label: 'Trusted sender context',
      points: 0,
      kind: 'trust',
      detail: trust.reasons.join('; '),
    });
  }

  let normalised = normaliseScore(score);
  const strongCritical = findings.find((f) => f.severity === 'critical' && f.confidence >= 0.9);
  if (strongCritical && normalised < CRITICAL_FLOOR) {
    contributions.push({
      label: 'Critical indicator floor',
      points: round(CRITICAL_FLOOR - normalised),
      kind: 'correlation',
      detail: `"${strongCritical.title}" is sufficient on its own for at least high risk`,
    });
    normalised = CRITICAL_FLOOR;
  }
  const finalScore = Math.max(0, Math.min(100, Math.round(normalised)));
  const level = levelFor(finalScore);
  const classification = classificationFor(finalScore);
  return {
    score: finalScore,
    level,
    classification,
    ruleScore: round(ruleScore),
    rawPoints: round(Math.max(0, score)),
    contributions: contributions.sort((a, b) => Math.abs(b.points) - Math.abs(a.points)),
    trustedContext: trust.trusted,
    summary: summarise(findings, ml, level, classification, trust),
  };
}

function summarise(
  findings: Finding[],
  ml: MlAssessment,
  level: RiskLevel,
  classification: Classification,
  trust: TrustContext,
): string {
  const ranked = [...findings]
    .filter((f) => f.severity !== 'info')
    .sort(
      (a, b) =>
        SEVERITY_POINTS[b.severity] * b.confidence - SEVERITY_POINTS[a.severity] * a.confidence,
    );
  const lead = ranked.slice(0, 3).map((f) => f.title);
  const parts = [
    `${level === 'safe' ? 'No significant risk' : `${level[0]!.toUpperCase()}${level.slice(1)} risk`} - classified ${classification}.`,
    lead.length
      ? `Key evidence: ${lead.join('; ')}.`
      : 'No rule-based indicators of phishing were found.',
  ];
  if (ml.available && ml.probability !== undefined) {
    const agrees = (ml.label === 'phishing') === (classification !== 'legitimate');
    parts.push(
      `The ML classifier estimates ${(ml.probability * 100).toFixed(0)}% phishing probability${agrees ? ', consistent with the rule evidence' : ', which the rule evidence does not support'}.`,
    );
  }
  if (trust.trusted)
    parts.push('The sender is authenticated and its links stay on its own domain.');
  return parts.join(' ');
}
