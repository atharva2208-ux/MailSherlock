import type { Severity, TextSpan } from '../../models/analysis.js';
import type { IntentId } from '../../services/analyzers/contentSignals.js';
import type { DetectionContext, DetectorFinding } from '../types.js';

export interface IntentRule {
  intents: IntentId[];
  /** Minimum combined score for each severity, checked from most to least severe. */
  thresholds: Partial<Record<Severity, number>>;
  spec: Pick<DetectorFinding, 'title' | 'whyItMatters' | 'recommendation' | 'attack'> & {
    describe: (labels: string[]) => string;
  };
  scoreGroup?: string;
}

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function intentFinding(ctx: DetectionContext, rule: IntentRule): DetectorFinding[] {
  const present = rule.intents.map((id) => ctx.content.intents[id]).filter((i) => i !== undefined);
  if (!present.length) return [];
  const score = present.reduce((sum, i) => sum + i.score, 0);
  const severity = ORDER.find(
    (level) => rule.thresholds[level] !== undefined && score >= rule.thresholds[level]!,
  );
  if (!severity) return [];
  const spans: TextSpan[] = present.flatMap((i) => i.spans).sort((a, b) => a.start - b.start);
  const quotes = [...new Set(spans.map((s) => s.text.trim()))].slice(0, 6);
  return [
    {
      severity,
      confidence: Math.min(0.95, Math.round((0.5 + score / 10) * 100) / 100),
      title: rule.spec.title,
      description: rule.spec.describe(present.map((i) => i.label)),
      whyItMatters: rule.spec.whyItMatters,
      evidence: [
        ...quotes.map((q) => ({ label: 'Phrase', value: `"${q}"` })),
        { label: 'Weighted score', value: score.toFixed(2) },
        ...(ctx.content.callToAction
          ? [{ label: 'Call to action', value: 'Message contains links or a form' }]
          : []),
      ],
      recommendation: rule.spec.recommendation,
      method:
        'Weighted phrase patterns grouped by manipulation intent, adjusted for co-occurring intents and calls to action (not single keywords).',
      attack: rule.spec.attack,
      spans,
      scoreGroup: rule.scoreGroup ?? 'content',
    },
  ];
}
