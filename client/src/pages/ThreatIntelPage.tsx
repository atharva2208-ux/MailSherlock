import { useQuery } from '@tanstack/react-query';
import { ExternalLink, Globe2 } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button } from '../components/common/Button';
import { Field, Panel } from '../components/common/Panel';
import { EmptyState, ErrorState, Skeleton } from '../components/common/States';
import { api } from '../services/api';
import type { ThreatIntelResult } from '../types';
import { PageHeader } from './PageHeader';

const VERDICT_COLOR: Record<string, string> = {
  malicious: 'var(--critical)',
  suspicious: 'var(--medium)',
  clean: 'var(--safe)',
  unknown: 'var(--muted)',
};

function ProviderRow({ result }: { result: ThreatIntelResult }) {
  return (
    <li className="grid gap-1 border-b border-line px-4 py-3 last:border-b-0 sm:grid-cols-[180px_120px_1fr]">
      <span className="font-medium">{result.provider}</span>
      <span
        style={{
          color:
            result.status === 'ok'
              ? VERDICT_COLOR[result.verdict ?? 'unknown']
              : result.status === 'error'
                ? 'var(--critical)'
                : 'var(--faint)',
        }}
      >
        {result.status === 'ok'
          ? (result.verdict ?? 'unknown')
          : result.status === 'not_configured'
            ? 'Not configured'
            : result.status === 'error'
              ? 'Error'
              : 'Skipped'}
      </span>
      <span className="text-[13px] text-muted">
        {result.status === 'not_configured'
          ? 'Add an API key in .env to enable. No request was made.'
          : result.summary}
        {result.link && (
          <a
            href={result.link}
            target="_blank"
            rel="noreferrer noopener"
            className="ml-2 inline-flex items-center gap-1 text-accent hover:underline"
          >
            Open <ExternalLink size={12} />
          </a>
        )}
      </span>
    </li>
  );
}

export default function ThreatIntelPage() {
  const [params, setParams] = useSearchParams();
  const indicator = params.get('q') ?? '';
  const [value, setValue] = useState(indicator);
  const query = useQuery({
    queryKey: ['intel', indicator],
    queryFn: () => api.threatIntel(indicator),
    enabled: Boolean(indicator),
    retry: false,
  });
  const local = query.data?.local;

  return (
    <div>
      <PageHeader
        title="Threat intelligence"
        description="Look up a domain or IPv4 address. Local analysis always runs; external providers are queried only when you configure their API keys, and URLs are never visited."
      />
      <form
        className="mb-4 flex max-w-xl gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) setParams({ q: value.trim().toLowerCase() });
        }}
      >
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="e.g. paypa1.com or 203.0.113.7"
          aria-label="Domain or IP address"
          className="h-9 flex-1 rounded-md border border-line bg-surface px-3 font-mono text-[13px] focus:border-accent focus:outline-none"
        />
        <Button type="submit" variant="primary" disabled={!value.trim()}>
          Look up
        </Button>
      </form>

      {!indicator && (
        <div className="rounded-lg border border-line bg-surface">
          <EmptyState icon={<Globe2 size={24} />} title="Enter an indicator to investigate">
            Domains are checked for brand look-alikes, homoglyphs, high-abuse TLDs and known
            services before any configured external source is consulted.
          </EmptyState>
        </div>
      )}
      {query.isLoading && <Skeleton className="h-64" />}
      {query.isError && (
        <ErrorState title="Lookup failed" message={(query.error as Error).message} />
      )}
      {query.data && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Local analysis" description="Computed offline by MailSherlock">
            {local ? (
              <dl>
                <Field label="Domain" mono>
                  {local.domain}
                </Field>
                {local.unicodeDomain !== local.domain && (
                  <Field label="Displays as">{local.unicodeDomain}</Field>
                )}
                <Field label="Registrable" mono>
                  {local.registrableDomain}
                </Field>
                <Field label="Public suffix" mono>
                  {local.publicSuffix || '-'}
                </Field>
                <Field label="Known service">
                  {local.officialBrand
                    ? `Official ${local.officialBrand} domain`
                    : local.freeMailProvider
                      ? 'Free-mail provider'
                      : local.urlShortener
                        ? 'URL shortener'
                        : 'No'}
                </Field>
                <Field label="High-abuse TLD">
                  {local.suspiciousTld ? <span className="text-medium">Yes</span> : 'No'}
                </Field>
                <Field label="Look-alike">
                  {local.lookalike ? (
                    <span className="text-critical">
                      {local.lookalike.detail} ({Math.round(local.lookalike.confidence * 100)}%
                      confidence)
                    </span>
                  ) : (
                    'No brand imitation detected'
                  )}
                </Field>
                <Field label="Homoglyphs">
                  {local.homoglyph ? (
                    local.homoglyph.mixedScript ? (
                      <span className="text-critical">
                        Mixes {local.homoglyph.scripts.join(' + ')}; reads as{' '}
                        {local.homoglyph.skeleton}
                      </span>
                    ) : (
                      `IDN using ${local.homoglyph.scripts.join(', ')}`
                    )
                  ) : (
                    'ASCII only'
                  )}
                </Field>
              </dl>
            ) : (
              <p className="text-[13px] text-muted">
                IP addresses have no local domain analysis; see external sources.
              </p>
            )}
          </Panel>
          <Panel title="External sources" bodyClassName="p-0">
            <ul>
              {query.data.external.map((r) => (
                <ProviderRow key={r.provider} result={r} />
              ))}
            </ul>
          </Panel>
        </div>
      )}
    </div>
  );
}
