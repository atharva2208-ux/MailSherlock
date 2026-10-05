import { ChevronRight } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import type { AnalysisResult } from '../../types';
import { formatBytes, formatDateTime } from '../../utils/format';
import { SeverityBadge } from '../common/Badge';
import { Field } from '../common/Panel';
import { AuthPanel } from '../authentication/AuthPanel';
import { ReceivedChain } from './ReceivedChain';

function Section({
  title,
  meta,
  children,
  defaultOpen = true,
}: {
  title: string;
  meta?: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details open={defaultOpen} className="group rounded-lg border border-line bg-surface">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3">
        <ChevronRight size={15} className="text-muted transition-transform group-open:rotate-90" />
        <span className="text-[13.5px] font-semibold">{title}</span>
        {meta && <span className="ml-auto text-[12px] text-muted">{meta}</span>}
      </summary>
      <div className="border-t border-line p-4">{children}</div>
    </details>
  );
}

export function HeadersPanel({ analysis }: { analysis: AnalysisResult }) {
  const m = analysis.metadata;
  const [filter, setFilter] = useState('');
  const suspicious = analysis.findings.filter((f) => ['header', 'sender'].includes(f.category));
  const headers = m.headers.filter(
    (h) =>
      !filter ||
      h.name.toLowerCase().includes(filter.toLowerCase()) ||
      h.value.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <div className="space-y-3">
      <Section title="Message metadata">
        <dl>
          <Field label="From">{m.from ? `${m.from.name} <${m.from.address}>` : '-'}</Field>
          <Field label="Reply-To">{m.replyTo?.map((r) => r.address).join(', ') ?? '-'}</Field>
          <Field label="Return-Path" mono>
            {m.returnPath ?? '-'}
          </Field>
          <Field label="To">{m.to.map((t) => t.address).join(', ') || '-'}</Field>
          {m.cc.length > 0 && <Field label="Cc">{m.cc.map((t) => t.address).join(', ')}</Field>}
          <Field label="Date">{m.date ? `${formatDateTime(m.date)} (${m.date})` : '-'}</Field>
          <Field label="Message-ID" mono>
            {m.messageId ?? '-'}
          </Field>
          <Field label="Mailer" mono>
            {m.xMailer ?? m.userAgent ?? '-'}
          </Field>
          <Field label="Size">{formatBytes(analysis.sizeBytes)}</Field>
          <Field label="SHA-256" mono>
            {analysis.sha256}
          </Field>
        </dl>
        {analysis.parseWarnings.length > 0 && (
          <ul className="mt-3 space-y-1 text-[12.5px] text-medium">
            {analysis.parseWarnings.map((w) => (
              <li key={w}>Parser warning: {w}</li>
            ))}
          </ul>
        )}
      </Section>
      <Section
        title="Authentication"
        meta={`SPF ${analysis.authentication.spf.state} · DKIM ${analysis.authentication.dkim.state} · DMARC ${analysis.authentication.dmarc.state}`.replace(
          /_/g,
          ' ',
        )}
      >
        <AuthPanel auth={analysis.authentication} compact />
      </Section>
      <Section
        title="Received chain"
        meta={`${analysis.received.length} hop${analysis.received.length === 1 ? '' : 's'}, origin first`}
      >
        <ReceivedChain hops={analysis.received} />
      </Section>
      <Section
        title="Suspicious headers"
        meta={`${suspicious.length} finding${suspicious.length === 1 ? '' : 's'}`}
      >
        {suspicious.length ? (
          <ul className="space-y-2">
            {suspicious.map((f) => (
              <li key={f.id} className="flex gap-3 text-[13px]">
                <SeverityBadge severity={f.severity} />
                <span>
                  <span className="font-medium">{f.title}.</span>{' '}
                  <span className="text-muted">{f.description}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[13px] text-muted">No header inconsistencies were detected.</p>
        )}
      </Section>
      <Section
        title="All headers"
        meta={`${m.headers.length} in original order`}
        defaultOpen={false}
      >
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter headers"
          aria-label="Filter headers"
          className="mb-3 h-8 w-full max-w-xs rounded-md border border-line bg-sunken px-3 text-[13px] focus:border-accent focus:outline-none"
        />
        <div className="max-h-[60vh] overflow-auto">
          <table className="w-full text-left text-[12.5px]">
            <tbody>
              {headers.map((h, i) => (
                <tr key={i} className="border-b border-line align-top last:border-b-0">
                  <th scope="row" className="w-48 py-1.5 pr-4 font-mono font-medium text-accent">
                    {h.name}
                  </th>
                  <td className="py-1.5 font-mono break-all">{h.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}
