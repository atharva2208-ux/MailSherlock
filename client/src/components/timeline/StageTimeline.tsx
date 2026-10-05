import type { AnalysisResult } from '../../types';
import { formatDateTime } from '../../utils/format';
import { Panel } from '../common/Panel';

/** Two timelines: the message's own journey, and how MailSherlock analysed it. */
export function StageTimeline({ analysis }: { analysis: AnalysisResult }) {
  const events = [
    ...(analysis.metadata.date
      ? [{ at: analysis.metadata.date, label: 'Date header (set by sender)', tone: 'var(--faint)' }]
      : []),
    ...analysis.received
      .filter((h) => h.timestamp)
      .map((h, i) => ({
        at: h.timestamp!,
        label: `${i === 0 ? 'First relay' : `Relay hop ${h.index}`}: ${h.by ?? 'unknown'}`,
        tone: h.flags.length ? 'var(--high)' : 'var(--low)',
      })),
    { at: analysis.createdAt, label: 'Analysed by MailSherlock', tone: 'var(--accent)' },
  ].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  const total = analysis.stages.reduce((s, x) => s + x.durationMs, 0);
  const max = Math.max(...analysis.stages.map((s) => s.durationMs), 1);

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Message timeline">
        <ol className="relative space-y-4 border-l border-line pl-5">
          {events.map((e, i) => (
            <li key={i} className="relative text-[13px]">
              <span
                className="absolute top-1.5 -left-[25px] h-2.5 w-2.5 rounded-full border-2 border-surface"
                style={{ background: e.tone }}
              />
              <p className="font-medium">{e.label}</p>
              <p className="text-[12px] text-muted">{formatDateTime(e.at)}</p>
            </li>
          ))}
        </ol>
      </Panel>
      <Panel
        title="Analysis pipeline"
        description={`${total.toFixed(0)} ms end to end, measured by the server`}
      >
        <ul className="space-y-2">
          {analysis.stages.map((s) => (
            <li
              key={s.id}
              className="grid grid-cols-[150px_1fr_64px] items-center gap-3 text-[13px]"
            >
              <span className={s.status === 'skipped' ? 'text-faint' : undefined}>{s.label}</span>
              <span className="h-1.5 rounded-full bg-raised" title={s.detail}>
                <span
                  className="block h-full rounded-full"
                  style={{
                    width: `${Math.max(1.5, (s.durationMs / max) * 100)}%`,
                    background:
                      s.status === 'skipped'
                        ? 'var(--faint)'
                        : s.status === 'failed'
                          ? 'var(--critical)'
                          : 'var(--accent)',
                  }}
                />
              </span>
              <span className="text-right text-[12px] tabular-nums text-muted">
                {s.status === 'skipped' ? 'skipped' : `${s.durationMs.toFixed(1)} ms`}
              </span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
