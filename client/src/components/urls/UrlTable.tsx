import { ChevronRight, ShieldCheck } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';
import { SEVERITY_ORDER } from '../../constants/severity';
import type { ExtractedUrl, Severity } from '../../types';
import { cx } from '../../utils/format';
import { LevelDot, SeverityBadge } from '../common/Badge';
import { Indicator } from '../common/Indicator';
import { EmptyState } from '../common/States';

const SOURCE_LABEL = { anchor: 'Link', text: 'Text', form: 'Form action', image: 'Image' } as const;
const rank = (risk: ExtractedUrl['risk']) => (risk === 'none' ? 5 : SEVERITY_ORDER.indexOf(risk));

/** Every URL in the message. Nothing here is ever fetched or made clickable. */
export function UrlTable({ urls }: { urls: ExtractedUrl[] }) {
  const [query, setQuery] = useState('');
  const [onlyRisky, setOnlyRisky] = useState(false);
  const [sort, setSort] = useState<'risk' | 'domain'>('risk');
  const [open, setOpen] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    return urls
      .filter(
        (u) =>
          (!onlyRisky || u.risk !== 'none') &&
          (!q || u.url.toLowerCase().includes(q) || (u.anchorText ?? '').toLowerCase().includes(q)),
      )
      .sort((a, b) =>
        sort === 'risk'
          ? rank(a.risk) - rank(b.risk)
          : a.registrableDomain.localeCompare(b.registrableDomain),
      );
  }, [urls, query, onlyRisky, sort]);

  if (!urls.length)
    return <EmptyState icon={<ShieldCheck size={22} />} title="No URLs in this message" />;

  return (
    <div className="rounded-lg border border-line bg-surface">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search URLs"
          aria-label="Search URLs"
          className="h-8 w-56 rounded-md border border-line bg-sunken px-3 text-[13px] focus:border-accent focus:outline-none"
        />
        <label className="flex items-center gap-2 text-[12.5px] text-muted">
          <input
            type="checkbox"
            checked={onlyRisky}
            onChange={(e) => setOnlyRisky(e.target.checked)}
            className="accent-[var(--accent)]"
          />
          Only URLs with indicators
        </label>
        <span className="ml-auto text-[12px] text-muted">
          {rows.length} of {urls.length} · never visited automatically
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-[13px]">
          <thead className="text-[12px] text-muted">
            <tr className="border-b border-line">
              <th scope="col" className="w-8" />
              <th scope="col" className="w-24 px-2 py-2 font-medium">
                <button
                  type="button"
                  onClick={() => setSort('risk')}
                  className={cx(sort === 'risk' && 'text-text')}
                  aria-sort={sort === 'risk' ? 'ascending' : undefined}
                >
                  Risk
                </button>
              </th>
              <th scope="col" className="px-2 py-2 font-medium">
                URL
              </th>
              <th scope="col" className="w-48 px-2 py-2 font-medium">
                <button
                  type="button"
                  onClick={() => setSort('domain')}
                  className={cx(sort === 'domain' && 'text-text')}
                >
                  Domain
                </button>
              </th>
              <th scope="col" className="w-24 px-2 py-2 font-medium">
                Type
              </th>
              <th scope="col" className="w-64 px-2 py-2 font-medium">
                Indicators
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => (
              <Fragment key={u.id || u.url}>
                <tr
                  className="cursor-pointer border-b border-line hover:bg-raised"
                  onClick={() => setOpen(open === u.id ? null : u.id)}
                >
                  <td className="pl-3">
                    <button
                      type="button"
                      aria-expanded={open === u.id}
                      aria-label="Show URL details"
                      className="flex text-muted"
                      onClick={(e) => (e.stopPropagation(), setOpen(open === u.id ? null : u.id))}
                    >
                      <ChevronRight
                        size={14}
                        className={cx('transition-transform', open === u.id && 'rotate-90')}
                      />
                    </button>
                  </td>
                  <td className="px-2 py-2">
                    {u.risk === 'none' ? (
                      <LevelDot level="none" label="None" />
                    ) : (
                      <SeverityBadge severity={u.risk as Severity} />
                    )}
                  </td>
                  <td className="max-w-0 px-2 py-2">
                    <Indicator value={u.url} />
                  </td>
                  <td className="truncate px-2 py-2 font-mono text-[12px]">
                    {u.unicodeHost ?? u.registrableDomain}
                  </td>
                  <td className="px-2 py-2 text-muted">{SOURCE_LABEL[u.source]}</td>
                  <td className="truncate px-2 py-2 text-[12.5px]">
                    {u.indicators.length ? (
                      `${u.indicators[0]!.label}${u.indicators.length > 1 ? ` +${u.indicators.length - 1}` : ''}`
                    ) : (
                      <span className="text-faint">-</span>
                    )}
                  </td>
                </tr>
                {open === u.id && (
                  <tr className="border-b border-line bg-sunken">
                    <td />
                    <td colSpan={5} className="px-2 py-3">
                      <dl className="grid gap-x-6 gap-y-1 text-[12.5px] md:grid-cols-[120px_1fr]">
                        <dt className="text-muted">Full URL</dt>
                        <dd className="font-mono break-all">{u.url}</dd>
                        <dt className="text-muted">Host</dt>
                        <dd className="font-mono">
                          {u.host}
                          {u.unicodeHost && ` (displays as ${u.unicodeHost})`}
                        </dd>
                        {u.anchorText && (
                          <>
                            <dt className="text-muted">Link text</dt>
                            <dd>{u.anchorText}</dd>
                          </>
                        )}
                        <dt className="text-muted">Indicators</dt>
                        <dd>
                          {u.indicators.length ? (
                            <ul className="space-y-1">
                              {u.indicators.map((i) => (
                                <li key={i.id} className="flex items-center gap-2">
                                  <SeverityBadge severity={i.severity} />
                                  {i.label}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            'None'
                          )}
                        </dd>
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
