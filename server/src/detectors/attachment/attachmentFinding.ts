import type { AttachmentInfo, Severity } from '../../models/analysis.js';
import type { DetectorFinding } from '../types.js';
import { maxSeverity } from '../../services/analyzers/urls.js';
import { ATTACK } from '../types.js';

export function attachmentFinding(
  attachments: AttachmentInfo[],
  indicatorIds: string[],
  spec: Pick<DetectorFinding, 'title' | 'whyItMatters' | 'recommendation' | 'method'> & {
    confidence: number;
    describe: (names: string[]) => string;
    attack?: string[];
  },
): DetectorFinding[] {
  const hits = attachments.filter((a) => a.indicators.some((i) => indicatorIds.includes(i.id)));
  if (!hits.length) return [];
  const severities = hits.flatMap((a) =>
    a.indicators.filter((i) => indicatorIds.includes(i.id)).map((i) => i.severity),
  );
  return [
    {
      severity: maxSeverity(severities) as Severity,
      confidence: spec.confidence,
      title: spec.title,
      description: spec.describe(hits.map((h) => h.filename)),
      whyItMatters: spec.whyItMatters,
      evidence: hits.slice(0, 5).flatMap((a) => [
        {
          label: a.filename,
          value: a.indicators
            .filter((i) => indicatorIds.includes(i.id))
            .map((i) => i.label)
            .join('; '),
        },
        { label: 'SHA-256', value: a.sha256 },
      ]),
      recommendation: spec.recommendation,
      method: spec.method,
      attack: spec.attack ?? [ATTACK.spearphishingAttachment],
      scoreGroup: 'attachment',
    },
  ];
}
