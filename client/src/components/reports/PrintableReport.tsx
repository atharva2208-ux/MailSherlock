import type { ReactNode } from 'react';
import {
  CATEGORY_LABEL,
  CLASSIFICATION_LABEL,
  FEEDBACK_LABEL,
  LEVEL_COLOR,
  RISK_LABEL,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
} from '../../constants/severity';
import type { AnalysisResult } from '../../types';
import { defang, formatBytes, formatDateTime, pct } from '../../utils/format';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="break-inside-avoid-page border-t border-line pt-4">
      <h2 className="mb-2 text-[15px] font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Rows({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <table className="w-full text-[12.5px]">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k} className="align-top">
            <th scope="row" className="w-40 py-0.5 pr-4 text-left font-normal text-muted">
              {k}
            </th>
            <td className="py-0.5 break-all">{v ?? '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Investigation report laid out for paper: indicators are defanged, nothing is clickable. */
export function PrintableReport({ analysis }: { analysis: AnalysisResult }) {
  const findings = [...analysis.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const recommendations = [
    ...new Set(findings.filter((f) => f.severity !== 'info').map((f) => f.recommendation)),
  ];
  const m = analysis.metadata;
  const color = LEVEL_COLOR[analysis.risk.level];
  return (
    <article className="mx-auto max-w-[800px] space-y-5 bg-surface p-10 text-text print:p-0">
      <header className="flex items-start justify-between gap-6">
        <div>
          <p className="text-[13px] font-semibold text-accent">MailSherlock</p>
          <h1 className="text-[24px] leading-tight font-semibold">
            Email Security Investigation Report
          </h1>
          <p className="mt-1 text-[12px] text-muted">
            {analysis.id} · generated {formatDateTime(new Date().toISOString())} · engine v
            {analysis.engineVersion}
          </p>
        </div>
        <div className="text-right">
          <p className="text-[40px] leading-none font-semibold tabular-nums" style={{ color }}>
            {analysis.risk.score}
          </p>
          <p className="text-[12.5px] font-semibold" style={{ color }}>
            {RISK_LABEL[analysis.risk.level]} risk ·{' '}
            {CLASSIFICATION_LABEL[analysis.risk.classification]}
          </p>
        </div>
      </header>

      <Section title="Executive summary">
        <p className="text-[13px] leading-relaxed">{analysis.risk.summary}</p>
        {analysis.feedback && (
          <p className="mt-2 text-[12.5px]">
            Analyst verdict: <strong>{FEEDBACK_LABEL[analysis.feedback.verdict]}</strong>
            {analysis.feedback.notes ? ` - ${analysis.feedback.notes}` : ''}
          </p>
        )}
      </Section>

      <Section title="Email metadata">
        <Rows
          rows={[
            ['Subject', m.subject],
            ['From', m.from ? `${m.from.name} <${m.from.address}>` : undefined],
            ['Reply-To', m.replyTo?.map((r) => r.address).join(', ')],
            ['Return-Path', m.returnPath],
            ['To', m.to.map((t) => t.address).join(', ')],
            ['Date', m.date ? formatDateTime(m.date) : undefined],
            ['Message-ID', m.messageId],
            [
              'SHA-256',
              <code key="h" className="font-mono text-[11.5px]">
                {analysis.sha256}
              </code>,
            ],
            ['Size', formatBytes(analysis.sizeBytes)],
          ]}
        />
      </Section>

      <Section title="Authentication results">
        <Rows
          rows={(['spf', 'dkim', 'dmarc'] as const).map((k) => [
            k.toUpperCase(),
            `${analysis.authentication[k].state.replace('_', ' ')}${analysis.authentication[k].result ? ` (${analysis.authentication[k].result})` : ''}${analysis.authentication[k].domain ? ` · ${analysis.authentication[k].domain}` : ''}`,
          ])}
        />
      </Section>

      <Section title="Header analysis">
        <ol className="space-y-0.5 text-[12px]">
          {analysis.received.map((h) => (
            <li key={h.index} className="font-mono">
              {h.index}. {h.from ?? '?'} → {h.by ?? '?'} {h.timestamp ? `@ ${h.timestamp}` : ''}{' '}
              {h.flags.length ? `[${h.flags.join('; ')}]` : ''}
            </li>
          ))}
          {!analysis.received.length && <li className="text-muted">No Received headers.</li>}
        </ol>
      </Section>

      <Section title={`Detected indicators (${findings.length})`}>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="border-b border-line text-left text-muted">
              <th className="w-20 py-1 font-medium">Severity</th>
              <th className="py-1 font-medium">Finding</th>
              <th className="w-28 py-1 font-medium">Category</th>
              <th className="w-16 py-1 text-right font-medium">Conf.</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-b border-line align-top">
                <td className="py-1 font-semibold" style={{ color: LEVEL_COLOR[f.severity] }}>
                  {SEVERITY_LABEL[f.severity]}
                </td>
                <td className="py-1">
                  <span className="font-medium">{f.title}.</span> {f.description}
                </td>
                <td className="py-1">{CATEGORY_LABEL[f.category]}</td>
                <td className="py-1 text-right tabular-nums">{pct(f.confidence, 0)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="URL analysis">
        {analysis.urls.filter((u) => u.source !== 'image').length ? (
          <ul className="space-y-1 text-[12px]">
            {analysis.urls
              .filter((u) => u.source !== 'image')
              .slice(0, 25)
              .map((u) => (
                <li key={u.id} className="break-all">
                  <code className="font-mono">{defang(u.url)}</code>
                  {u.indicators.length > 0 && (
                    <span className="text-muted">
                      {' '}
                      - {u.indicators.map((i) => i.label).join('; ')}
                    </span>
                  )}
                </li>
              ))}
          </ul>
        ) : (
          <p className="text-[12.5px] text-muted">No URLs.</p>
        )}
      </Section>

      <Section title="Attachment analysis">
        {analysis.attachments.length ? (
          <Rows
            rows={analysis.attachments.map((a) => [
              a.filename,
              <span key={a.id} className="font-mono text-[11.5px]">
                {a.sha256} · {formatBytes(a.size)}
                {a.indicators.length ? ` · ${a.indicators.map((i) => i.label).join('; ')}` : ''}
              </span>,
            ])}
          />
        ) : (
          <p className="text-[12.5px] text-muted">No attachments.</p>
        )}
      </Section>

      <Section title="Machine learning assessment">
        <p className="text-[12.5px]">
          {analysis.ml.available
            ? `${analysis.ml.modelName} v${analysis.ml.modelVersion}: ${pct(analysis.ml.probability)} phishing probability (threshold ${pct(analysis.ml.threshold)}, ${analysis.ml.confidence} confidence). Top signals: ${
                (analysis.ml.signals ?? [])
                  .filter((s) => s.weight > 0)
                  .slice(0, 5)
                  .map((s) => s.feature)
                  .join(', ') || 'none'
              }.`
            : 'Machine learning enrichment unavailable. Results are based on rule-based analysis.'}
        </p>
      </Section>

      <Section title="Threat intelligence">
        <p className="text-[12.5px]">
          {analysis.threatIntel.length
            ? analysis.threatIntel
                .map((t) => `${t.provider}: ${t.target} - ${t.summary}`)
                .join('; ')
            : 'No external threat-intelligence providers were queried for this analysis.'}
        </p>
      </Section>

      <Section title="Score breakdown">
        <Rows
          rows={analysis.risk.contributions.map((c) => [
            c.label,
            `${c.points > 0 ? '+' : ''}${c.points}${c.detail ? ` - ${c.detail}` : ''}`,
          ])}
        />
      </Section>

      <Section title="Recommendations">
        {recommendations.length ? (
          <ul className="list-disc space-y-1 pl-5 text-[12.5px]">
            {recommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        ) : (
          <p className="text-[12.5px]">No action required beyond normal handling.</p>
        )}
      </Section>
    </article>
  );
}
