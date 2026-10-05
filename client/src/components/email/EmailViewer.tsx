import { MousePointerClick } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { AnalysisResult, Finding, TextSpan } from '../../types';
import { cx, formatDateTime, pct } from '../../utils/format';
import { SeverityBadge } from '../common/Badge';
import { Button } from '../common/Button';
import { SCORE_GROUP_LABEL, SEVERITY_ORDER } from '../../constants/severity';
import { HighlightedContent } from './HighlightedContent';
import { HtmlPreview } from './HtmlPreview';

/**
 * Link findings carry the URLs they are about rather than text offsets; locate
 * those URLs in the body so they can be highlighted alongside language evidence.
 */
function withUrlSpans(findings: Finding[], text: string): Finding[] {
  return findings.map((f) => {
    if (f.spans?.length || !f.relatedUrls?.length) return f;
    const spans: TextSpan[] = [];
    for (const url of f.relatedUrls) {
      for (
        let at = text.indexOf(url);
        at >= 0 && spans.length < 12;
        at = text.indexOf(url, at + url.length)
      ) {
        spans.push({ start: at, end: at + url.length, text: url });
      }
    }
    return spans.length ? { ...f, spans } : f;
  });
}

function mostSevere(findings: Finding[]): Finding | undefined {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      b.confidence - a.confidence,
  )[0];
}

function EmailHeaderBlock({ analysis }: { analysis: AnalysisResult }) {
  const m = analysis.metadata;
  const rows: [string, string | undefined][] = [
    ['From', m.from ? `${m.from.name ? `${m.from.name} ` : ''}<${m.from.address}>` : undefined],
    ['Reply-To', m.replyTo?.map((r) => r.address).join(', ')],
    ['To', m.to.map((t) => t.address).join(', ') || undefined],
    ['Date', m.date ? formatDateTime(m.date) : undefined],
  ];
  return (
    <div className="border-b border-line px-5 py-4">
      <h3 className="text-[17px] leading-snug font-semibold">{m.subject || '(no subject)'}</h3>
      <dl className="mt-2 grid gap-x-6 gap-y-0.5 text-[13px] sm:grid-cols-[auto_1fr]">
        {rows
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd
                className={cx(
                  'min-w-0 break-all',
                  k === 'Reply-To' &&
                    m.replyTo?.some((r) => r.domain !== m.from?.domain) &&
                    'text-high',
                )}
              >
                {v}
              </dd>
            </div>
          ))}
      </dl>
    </div>
  );
}

/**
 * The email itself, with every piece of text evidence highlighted. Selecting a
 * highlight opens the finding it supports and shows which part of the score it
 * feeds - the email -> finding -> score chain.
 */
export function EmailViewer({
  analysis,
  onOpenFinding,
}: {
  analysis: AnalysisResult;
  onOpenFinding: (id: string) => void;
}) {
  const evidenceFindings = useMemo(
    () => withUrlSpans(analysis.findings, analysis.body.text).filter((f) => f.spans?.length),
    [analysis.findings, analysis.body.text],
  );
  const [mode, setMode] = useState<'text' | 'html'>('text');
  const [selected, setSelected] = useState<string | null>(
    () => mostSevere(evidenceFindings)?.id ?? null,
  );
  const finding =
    evidenceFindings.find((f) => f.id === selected) ??
    analysis.findings.find((f) => f.id === selected);
  const contribution = finding
    ? analysis.risk.contributions.find((c) => c.label === SCORE_GROUP_LABEL[finding.scoreGroup])
    : undefined;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
      <div className="min-w-0 rounded-lg border border-line bg-surface">
        <EmailHeaderBlock analysis={analysis} />
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-2">
          <div role="radiogroup" aria-label="Body view" className="flex gap-1">
            <Button
              size="sm"
              variant={mode === 'text' ? 'secondary' : 'ghost'}
              aria-pressed={mode === 'text'}
              onClick={() => setMode('text')}
            >
              Text with evidence
            </Button>
            <Button
              size="sm"
              variant={mode === 'html' ? 'secondary' : 'ghost'}
              aria-pressed={mode === 'html'}
              disabled={!analysis.body.sanitizedHtml}
              onClick={() => setMode('html')}
            >
              Rendered HTML
            </Button>
          </div>
          <span className="text-[12px] text-muted">
            {mode === 'text'
              ? `${evidenceFindings.reduce((n, f) => n + (f.spans?.length ?? 0), 0)} highlighted phrases`
              : 'Sanitised · scripts, images and links disabled'}
          </span>
        </div>
        <div className="px-5 py-4">
          {mode === 'html' && analysis.body.sanitizedHtml ? (
            <HtmlPreview html={analysis.body.sanitizedHtml} />
          ) : analysis.body.text ? (
            <HighlightedContent
              text={analysis.body.text}
              findings={evidenceFindings}
              activeId={selected}
              onSelect={setSelected}
            />
          ) : (
            <p className="text-[13px] text-muted">This message has no readable body.</p>
          )}
          {analysis.body.truncated && (
            <p className="mt-3 text-[12px] text-muted">
              Body truncated to the first 100,000 characters for analysis.
            </p>
          )}
        </div>
      </div>

      <aside
        aria-label="Evidence inspector"
        className="h-fit rounded-lg border border-line bg-surface xl:sticky xl:top-[68px]"
      >
        <p className="border-b border-line px-4 py-2.5 text-[13px] font-semibold">
          Evidence inspector
        </p>
        {finding ? (
          <div className="space-y-3 p-4 text-[13px]">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-[12px] text-muted">
                {pct(finding.confidence, 0)} confidence
              </span>
            </div>
            <p className="font-semibold">{finding.title}</p>
            <ul className="space-y-1">
              {(finding.spans ?? []).slice(0, 4).map((s, i) => (
                <li key={i} className="border-l-2 border-high pl-2 text-[12.5px] text-muted italic">
                  “{s.text}”
                </li>
              ))}
            </ul>
            <p>{finding.whyItMatters}</p>
            {finding.adjustment && (
              <p className="text-[12.5px] text-muted">
                Lowered from {finding.adjustment.from}: sender is authenticated.
              </p>
            )}
            {contribution && (
              <p className="rounded-md bg-sunken px-3 py-2 text-[12.5px]">
                Feeds <strong>{contribution.label}</strong>, which adds{' '}
                <strong>+{contribution.points}</strong> to the score.
              </p>
            )}
            <Button size="sm" onClick={() => onOpenFinding(finding.id)}>
              Open finding
            </Button>
          </div>
        ) : (
          <div className="flex gap-2 p-4 text-[13px] text-muted">
            <MousePointerClick size={16} className="shrink-0" />
            {evidenceFindings.length
              ? 'Select highlighted text to see the finding it supports.'
              : 'No text-based evidence was found in the body.'}
          </div>
        )}
      </aside>
    </div>
  );
}
