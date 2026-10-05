import type { ExtractedUrl, Severity } from '../../models/analysis.js';
import type { DetectorFinding } from '../types.js';
import { maxSeverity } from '../../services/analyzers/urls.js';

/**
 * Collapse one indicator type across all URLs into a single finding, so ten
 * links to the same IP produce one piece of evidence rather than ten.
 */
export function aggregateUrlIndicator(
  urls: ExtractedUrl[],
  indicatorIds: string[],
  build: (matches: { url: ExtractedUrl; label: string; severity: Severity }[]) => Omit<
    DetectorFinding,
    'severity' | 'evidence' | 'relatedUrls' | 'scoreGroup'
  > & {
    severity?: Severity;
  },
): DetectorFinding[] {
  const matches = urls.flatMap((url) =>
    url.indicators
      .filter((i) => indicatorIds.includes(i.id))
      .map((i) => ({ url, label: i.label, severity: i.severity })),
  );
  // Tracking images rarely matter on their own; only links and forms are actionable.
  const actionable = matches.filter((m) => m.url.source !== 'image');
  const relevant = actionable.length ? actionable : [];
  if (!relevant.length) return [];
  const spec = build(relevant);
  const severity = spec.severity ?? (maxSeverity(relevant.map((m) => m.severity)) as Severity);
  return [
    {
      ...spec,
      severity,
      evidence: relevant.slice(0, 6).map((m) => ({
        label: m.url.registrableDomain || m.url.host || 'URL',
        value: `${m.url.url.slice(0, 300)} - ${m.label}`,
      })),
      relatedUrls: [...new Set(relevant.map((m) => m.url.url))].slice(0, 10),
      scoreGroup: 'url',
    },
  ];
}
