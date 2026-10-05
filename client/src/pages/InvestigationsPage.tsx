import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, FolderSearch, X } from 'lucide-react';
import { useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Button } from '../components/common/Button';
import { EmptyState, ErrorState, Skeleton } from '../components/common/States';
import { InvestigationsTable, type SortField } from '../components/dashboard/InvestigationsTable';
import { CLASSIFICATION_LABEL, LEVEL_COLOR, RISK_LABEL } from '../constants/severity';
import { api } from '../services/api';
import type { Classification, RiskLevel } from '../types';
import { cx } from '../utils/format';
import { PageHeader } from './PageHeader';

const LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'safe'];
const CLASSES: Classification[] = ['phishing', 'suspicious', 'legitimate'];
const PAGE_SIZE = 25;

export function InvestigationsPage() {
  const [params, setParams] = useSearchParams();
  const state = useMemo(
    () => ({
      search: params.get('search') ?? '',
      riskLevel: params.get('riskLevel')?.split(',').filter(Boolean) ?? [],
      classification: params.get('classification')?.split(',').filter(Boolean) ?? [],
      from: params.get('from') ?? '',
      to: params.get('to') ?? '',
      sort: (params.get('sort') as SortField) ?? 'created_at',
      order: (params.get('order') as 'asc' | 'desc') ?? 'desc',
      page: Number(params.get('page') ?? 1),
    }),
    [params],
  );
  const update = (patch: Record<string, string | string[] | number | undefined>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries({ page: 1, ...patch })) {
      const text = Array.isArray(value)
        ? value.join(',')
        : value === undefined
          ? ''
          : String(value);
      if (!text || (key === 'page' && text === '1')) next.delete(key);
      else next.set(key, text);
    }
    setParams(next, { replace: true });
  };
  const toggle = (key: 'riskLevel' | 'classification', value: string) => {
    const current = state[key];
    update({
      [key]: current.includes(value) ? current.filter((v) => v !== value) : [...current, value],
    });
  };

  const query = useQuery({
    queryKey: ['analyses', state],
    queryFn: () =>
      api.listAnalyses({
        ...state,
        pageSize: PAGE_SIZE,
        from: state.from || undefined,
        to: state.to || undefined,
      }),
    placeholderData: keepPreviousData,
  });
  const filtered =
    state.search || state.riskLevel.length || state.classification.length || state.from || state.to;
  const totalPages = query.data ? Math.max(1, Math.ceil(query.data.total / PAGE_SIZE)) : 1;

  return (
    <div>
      <PageHeader
        title="Investigations"
        description="Every analysed email, with its verdict, evidence count and analyst feedback."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input
          key={state.search}
          defaultValue={state.search}
          onKeyDown={(e) =>
            e.key === 'Enter' && update({ search: (e.target as HTMLInputElement).value.trim() })
          }
          onBlur={(e) =>
            e.target.value.trim() !== state.search && update({ search: e.target.value.trim() })
          }
          placeholder="Search sender, subject, file, ID or SHA-256"
          aria-label="Search investigations"
          className="h-8 w-72 rounded-md border border-line bg-surface px-3 text-[13px] focus:border-accent focus:outline-none"
        />
        <div
          role="group"
          aria-label="Risk level"
          className="flex rounded-md border border-line bg-surface p-0.5"
        >
          {LEVELS.map((level) => (
            <button
              key={level}
              type="button"
              aria-pressed={state.riskLevel.includes(level)}
              onClick={() => toggle('riskLevel', level)}
              className={cx(
                'flex h-7 items-center gap-1.5 rounded px-2 text-[12.5px]',
                state.riskLevel.includes(level)
                  ? 'bg-raised text-text'
                  : 'text-muted hover:text-text',
              )}
            >
              <span
                aria-hidden
                className="h-2 w-2 rounded-[2px]"
                style={{ background: LEVEL_COLOR[level] }}
              />
              {RISK_LABEL[level]}
            </button>
          ))}
        </div>
        <div
          role="group"
          aria-label="Classification"
          className="flex rounded-md border border-line bg-surface p-0.5"
        >
          {CLASSES.map((c) => (
            <button
              key={c}
              type="button"
              aria-pressed={state.classification.includes(c)}
              onClick={() => toggle('classification', c)}
              className={cx(
                'h-7 rounded px-2 text-[12.5px]',
                state.classification.includes(c)
                  ? 'bg-raised text-text'
                  : 'text-muted hover:text-text',
              )}
            >
              {CLASSIFICATION_LABEL[c]}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-[12.5px] text-muted">
          From
          <input
            type="date"
            value={state.from}
            onChange={(e) => update({ from: e.target.value })}
            className="h-8 rounded-md border border-line bg-surface px-2 text-[12.5px] text-text [color-scheme:inherit]"
          />
        </label>
        <label className="flex items-center gap-1.5 text-[12.5px] text-muted">
          To
          <input
            type="date"
            value={state.to}
            onChange={(e) => update({ to: e.target.value })}
            className="h-8 rounded-md border border-line bg-surface px-2 text-[12.5px] text-text"
          />
        </label>
        {filtered && (
          <Button
            size="sm"
            variant="ghost"
            icon={<X size={13} />}
            onClick={() => setParams({}, { replace: true })}
          >
            Clear filters
          </Button>
        )}
      </div>

      <div className="rounded-lg border border-line bg-surface">
        {query.isLoading ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="Loading investigations">
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-8" />
            ))}
          </div>
        ) : query.isError ? (
          <div className="p-4">
            <ErrorState
              title="Investigations could not be loaded"
              message={(query.error as Error).message}
            />
          </div>
        ) : !query.data?.items.length ? (
          filtered ? (
            <EmptyState
              title="No investigations match these filters"
              action={
                <Button size="sm" onClick={() => setParams({}, { replace: true })}>
                  Clear filters
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={<FolderSearch size={24} />}
              title="No investigations yet"
              action={
                <Link
                  to="/analyze"
                  className="inline-flex h-9 items-center rounded-md bg-accent px-3.5 text-[13.5px] font-semibold text-[#120d2e]"
                >
                  Analyze email
                </Link>
              }
            >
              Upload your first suspicious email to begin an investigation.
            </EmptyState>
          )
        ) : (
          <>
            <InvestigationsTable
              items={query.data.items}
              sort={{ field: state.sort, order: state.order }}
              onSort={(field) =>
                update({
                  sort: field,
                  order: state.sort === field && state.order === 'desc' ? 'asc' : 'desc',
                })
              }
            />
            <div className="flex items-center justify-between border-t border-line px-3 py-2 text-[12.5px] text-muted">
              <span>
                {(state.page - 1) * PAGE_SIZE + 1}–
                {Math.min(state.page * PAGE_SIZE, query.data.total)} of {query.data.total}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Previous page"
                  disabled={state.page <= 1}
                  onClick={() => update({ page: state.page - 1 })}
                  icon={<ChevronLeft size={14} />}
                />
                <span className="tabular-nums">
                  Page {state.page} of {totalPages}
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Next page"
                  disabled={state.page >= totalPages}
                  onClick={() => update({ page: state.page + 1 })}
                  icon={<ChevronRight size={14} />}
                />
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
