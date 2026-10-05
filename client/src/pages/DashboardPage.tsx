import { useQuery } from '@tanstack/react-query';
import { Inbox, ScanSearch } from 'lucide-react';
import { Link } from 'react-router-dom';
import { SeverityBadge } from '../components/common/Badge';
import { Panel } from '../components/common/Panel';
import { EmptyState, ErrorState, Skeleton } from '../components/common/States';
import { CategoryBars, HistoryChart, RiskDistribution } from '../components/dashboard/Charts';
import { InvestigationsTable } from '../components/dashboard/InvestigationsTable';
import { api } from '../services/api';
import { PageHeader } from './PageHeader';

export default function DashboardPage() {
  const stats = useQuery({ queryKey: ['stats'], queryFn: api.stats });
  const recent = useQuery({
    queryKey: ['analyses', 'recent'],
    queryFn: () => api.listAnalyses({ pageSize: 8 }),
  });
  const actions = (
    <Link
      to="/analyze"
      className="inline-flex h-9 items-center gap-1.5 rounded-md bg-accent px-3.5 text-[13.5px] font-semibold text-[#120d2e] hover:bg-accent-strong"
    >
      <ScanSearch size={15} /> Analyze email
    </Link>
  );

  if (stats.isLoading)
    return (
      <div className="space-y-4" aria-busy="true" aria-label="Loading dashboard">
        <Skeleton className="h-8 w-60" />
        <Skeleton className="h-24" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-64 lg:col-span-2" />
          <Skeleton className="h-64" />
        </div>
      </div>
    );
  if (stats.isError)
    return <ErrorState title="Dashboard unavailable" message={(stats.error as Error).message} />;
  const s = stats.data!;

  if (s.totals.investigations === 0) {
    return (
      <div>
        <PageHeader title="Dashboard" />
        <div className="rounded-lg border border-line bg-surface">
          <EmptyState icon={<Inbox size={26} />} title="No investigations yet" action={actions}>
            Upload your first suspicious email to begin an investigation. Statistics here are
            computed from the investigations you run.
          </EmptyState>
        </div>
      </div>
    );
  }

  const kpis = [
    { label: 'Investigations', value: s.totals.investigations },
    {
      label: 'Threats detected',
      value: s.totals.threats,
      color: 'var(--critical)',
      hint: 'classified phishing',
    },
    { label: 'Suspicious', value: s.totals.suspicious, color: 'var(--medium)' },
    { label: 'High-risk emails', value: s.totals.highRisk, hint: 'high or critical' },
    { label: 'Critical findings', value: s.totals.criticalFindings },
    {
      label: 'False positives',
      value: s.totals.falsePositives,
      hint: `from ${s.totals.feedbackCount} analyst review${s.totals.feedbackCount === 1 ? '' : 's'}`,
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Dashboard"
        description="Live view of everything analysed on this instance."
        actions={actions}
      />
      <section
        aria-label="Key figures"
        className="grid grid-cols-2 overflow-hidden rounded-lg border border-line bg-surface sm:grid-cols-3 xl:grid-cols-6"
      >
        {kpis.map((k) => (
          <div
            key={k.label}
            className="border-line px-4 py-3.5 [&:not(:last-child)]:border-r max-xl:[&:nth-child(3)]:border-r-0 max-xl:[&:nth-child(-n+3)]:border-b max-sm:[&:nth-child(2n)]:border-r-0"
          >
            <p className="text-[12.5px] text-muted">{k.label}</p>
            <p
              className="mt-0.5 text-[26px] leading-tight font-semibold tabular-nums"
              style={k.color ? { color: k.color } : undefined}
            >
              {k.value.toLocaleString()}
            </p>
            {k.hint && <p className="text-[11.5px] text-faint">{k.hint}</p>}
          </div>
        ))}
      </section>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          title="Analysis history"
          description="Last 30 days by classification"
          className="lg:col-span-2"
        >
          <HistoryChart history={s.history} />
        </Panel>
        <Panel title="Risk distribution">
          <RiskDistribution distribution={s.riskDistribution} />
          <div className="mt-4 border-t border-line pt-3 text-[13px]">
            <p className="mb-1.5 text-muted">Phishing vs legitimate</p>
            <p className="tabular-nums">
              <span className="text-critical">{s.classification.phishing} phishing</span> ·{' '}
              <span className="text-medium">{s.classification.suspicious} suspicious</span> ·{' '}
              <span className="text-safe">{s.classification.legitimate} legitimate</span>
            </p>
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Detection categories" description="Findings above informational, by category">
          <CategoryBars categories={s.categories} />
        </Panel>
        <Panel title="Common indicators" className="lg:col-span-2" bodyClassName="p-0">
          <ul>
            {s.topIndicators.map((i) => (
              <li
                key={i.title}
                className="grid grid-cols-[76px_1fr_auto] items-center gap-3 border-b border-line px-4 py-2 text-[13px] last:border-b-0"
              >
                <SeverityBadge severity={i.severity} />
                <span className="truncate">{i.title}</span>
                <span className="tabular-nums text-muted">{i.count}×</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <Panel
        title="Recent investigations"
        actions={
          <Link
            to="/investigations"
            className="rounded-md px-2.5 py-1 text-[12.5px] text-muted hover:bg-raised hover:text-text"
          >
            View all
          </Link>
        }
        bodyClassName="p-0"
      >
        {recent.data ? (
          <InvestigationsTable items={recent.data.items} compact />
        ) : (
          <Skeleton className="m-4 h-40" />
        )}
      </Panel>
    </div>
  );
}
