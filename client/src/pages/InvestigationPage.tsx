import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, Printer, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { FeedbackControl } from '../components/analysis/FeedbackControl';
import { ScoreBreakdown } from '../components/analysis/ScoreBreakdown';
import { VerdictBand } from '../components/analysis/VerdictBand';
import { AttachmentTable } from '../components/attachments/AttachmentTable';
import { AuthPanel } from '../components/authentication/AuthPanel';
import { SeverityBadge } from '../components/common/Badge';
import { Button, LinkButton } from '../components/common/Button';
import { Panel } from '../components/common/Panel';
import { ErrorState, Skeleton } from '../components/common/States';
import { Tabs } from '../components/common/Tabs';
import { useToast } from '../components/common/Toast';
import { EmailViewer } from '../components/email/EmailViewer';
import { RawSourceViewer } from '../components/email/RawSourceViewer';
import { FindingsPanel } from '../components/findings/FindingsPanel';
import { InvestigationGraph } from '../components/graph/InvestigationGraph';
import { HeadersPanel } from '../components/headers/HeadersPanel';
import { MlPanel } from '../components/ml/MlPanel';
import { StageTimeline } from '../components/timeline/StageTimeline';
import { UrlTable } from '../components/urls/UrlTable';
import { LEVEL_COLOR, SEVERITY_ORDER } from '../constants/severity';
import { api } from '../services/api';
import type { AnalysisResult } from '../types';
import { formatDateTime } from '../utils/format';

function Overview({
  analysis,
  go,
}: {
  analysis: AnalysisResult;
  go: (tab: string, finding?: string) => void;
}) {
  const top = [...analysis.findings]
    .filter((f) => f.severity !== 'info')
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        b.confidence - a.confidence,
    )
    .slice(0, 6);
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
      <div className="space-y-4">
        <Panel
          title="Key findings"
          actions={
            <Button size="sm" variant="ghost" onClick={() => go('findings')}>
              All {analysis.findings.length}
            </Button>
          }
          bodyClassName="p-0"
        >
          {top.length ? (
            <ul>
              {top.map((f) => (
                <li key={f.id} className="border-b border-line last:border-b-0">
                  <button
                    type="button"
                    onClick={() => go('findings', f.id)}
                    className="grid w-full grid-cols-[76px_1fr] items-start gap-3 px-4 py-2.5 text-left hover:bg-raised"
                  >
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0">
                      <span className="block text-[13.5px] font-medium">{f.title}</span>
                      <span className="block text-[12.5px] text-muted">{f.description}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="p-4 text-[13px] text-muted">No rule-based indicators were found.</p>
          )}
        </Panel>
        <Panel title="Relationships">
          <InvestigationGraph analysis={analysis} onNavigate={(tab) => go(tab)} />
          {!(analysis.metadata.from && (analysis.urls.length || analysis.metadata.replyTo)) && (
            <p className="text-[13px] text-muted">Not enough related infrastructure to draw.</p>
          )}
        </Panel>
      </div>
      <div className="space-y-4">
        <Panel title="How the score was built">
          <ScoreBreakdown risk={analysis.risk} />
        </Panel>
        <Panel
          title="Authentication"
          actions={
            <Button size="sm" variant="ghost" onClick={() => go('authentication')}>
              Details
            </Button>
          }
        >
          <AuthPanel auth={analysis.authentication} compact />
        </Panel>
        <Panel title="Analyst verdict">
          <FeedbackControl analysis={analysis} />
        </Panel>
      </div>
    </div>
  );
}

export function InvestigationPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const [params, setParams] = useSearchParams();
  const [focusFinding, setFocusFinding] = useState<string | null>(null);
  const tab = params.get('tab') ?? 'overview';
  const {
    data: analysis,
    error,
    isLoading,
  } = useQuery({ queryKey: ['analysis', id], queryFn: () => api.getAnalysis(id) });

  const remove = useMutation({
    mutationFn: () => api.deleteAnalysis(id),
    onSuccess: () => {
      notify('success', 'Investigation deleted');
      void queryClient.invalidateQueries({ queryKey: ['analyses'] });
      void queryClient.invalidateQueries({ queryKey: ['stats'] });
      navigate('/investigations');
    },
    onError: (e: Error) => notify('error', 'Delete failed', e.message),
  });

  const go = (next: string, finding?: string) => {
    setParams(next === 'overview' ? {} : { tab: next }, { replace: true });
    if (finding) setFocusFinding(finding);
  };

  if (isLoading)
    return (
      <div className="space-y-4" aria-busy="true" aria-label="Loading investigation">
        <Skeleton className="h-5 w-72" />
        <Skeleton className="h-56" />
        <Skeleton className="h-10" />
        <Skeleton className="h-80" />
      </div>
    );
  if (error || !analysis)
    return (
      <ErrorState
        title="Investigation unavailable"
        message={(error as Error)?.message ?? 'Not found'}
        action={
          <Link to="/investigations" className="text-accent hover:underline">
            Back to investigations
          </Link>
        }
      />
    );

  const mlContribution = analysis.risk.contributions.find((c) => c.kind === 'ml')?.points;
  const worstUrl = SEVERITY_ORDER.find((s) => analysis.urls.some((u) => u.risk === s));
  const worstAttachment = SEVERITY_ORDER.find((s) =>
    analysis.attachments.some((a) => a.risk === s),
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <nav aria-label="Breadcrumb" className="text-[12.5px] text-muted">
            <Link to="/investigations" className="hover:text-text">
              Investigations
            </Link>{' '}
            / <code className="font-mono">{analysis.id}</code>
          </nav>
          <h1
            className="mt-1 truncate text-[20px] font-semibold tracking-[-0.01em]"
            title={analysis.metadata.subject}
          >
            {analysis.metadata.subject || '(no subject)'}
          </h1>
          <p className="text-[13px] text-muted">
            {analysis.metadata.from?.address ?? 'unknown sender'} · {analysis.sourceName} · analysed{' '}
            {formatDateTime(analysis.createdAt)}
          </p>
        </div>
        <div className="no-print flex gap-2">
          <LinkButton
            size="sm"
            href={api.reportUrl(analysis.id)}
            download
            icon={<Download size={14} />}
            onClick={() =>
              notify('success', 'Report exported', 'JSON investigation report downloaded')
            }
          >
            Export JSON
          </LinkButton>
          <Button
            size="sm"
            icon={<Printer size={14} />}
            onClick={() => navigate(`/reports/${analysis.id}/print`)}
          >
            Printable report
          </Button>
          <Button
            size="sm"
            variant="danger"
            icon={<Trash2 size={14} />}
            disabled={remove.isPending}
            onClick={() => {
              if (
                window.confirm(
                  'Delete this investigation and its stored source? This cannot be undone.',
                )
              )
                remove.mutate();
            }}
          >
            Delete
          </Button>
        </div>
      </div>

      <VerdictBand analysis={analysis} />

      <Tabs
        label="Investigation sections"
        active={tab}
        onChange={(t) => go(t)}
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'email', label: 'Email' },
          { id: 'headers', label: 'Headers', count: analysis.received.length },
          { id: 'authentication', label: 'Authentication' },
          {
            id: 'urls',
            label: 'URLs',
            count: analysis.urls.length,
            tone: worstUrl ? LEVEL_COLOR[worstUrl] : undefined,
          },
          {
            id: 'attachments',
            label: 'Attachments',
            count: analysis.attachments.length,
            tone: worstAttachment ? LEVEL_COLOR[worstAttachment] : undefined,
          },
          { id: 'findings', label: 'Findings', count: analysis.findings.length },
          { id: 'ml', label: 'ML assessment' },
          { id: 'timeline', label: 'Timeline' },
          { id: 'raw', label: 'Raw source' },
        ]}
      >
        {tab === 'overview' && <Overview analysis={analysis} go={go} />}
        {tab === 'email' && (
          <EmailViewer analysis={analysis} onOpenFinding={(f) => go('findings', f)} />
        )}
        {tab === 'headers' && <HeadersPanel analysis={analysis} />}
        {tab === 'authentication' && <AuthPanel auth={analysis.authentication} />}
        {tab === 'urls' && <UrlTable urls={analysis.urls} />}
        {tab === 'attachments' && <AttachmentTable attachments={analysis.attachments} />}
        {tab === 'findings' && (
          <FindingsPanel
            key={focusFinding ?? 'all'}
            findings={analysis.findings}
            risk={analysis.risk}
            focusId={focusFinding}
          />
        )}
        {tab === 'ml' && <MlPanel ml={analysis.ml} mlPoints={mlContribution} />}
        {tab === 'timeline' && <StageTimeline analysis={analysis} />}
        {tab === 'raw' && <RawSourceViewer analysisId={analysis.id} />}
      </Tabs>
    </div>
  );
}
