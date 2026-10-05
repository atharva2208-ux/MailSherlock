import { Check, Circle, Loader2, Minus, X } from 'lucide-react';
import type { AnalysisStageId, StageTiming } from '../../types';
import { cx } from '../../utils/format';

const STAGE_ORDER: { id: AnalysisStageId; label: string }[] = [
  { id: 'parse', label: 'Parsing email' },
  { id: 'headers', label: 'Extracting headers' },
  { id: 'authentication', label: 'Analysing authentication' },
  { id: 'urls', label: 'Extracting URLs' },
  { id: 'content', label: 'Analysing content' },
  { id: 'attachments', label: 'Inspecting attachments' },
  { id: 'rules', label: 'Running detection engine' },
  { id: 'ml', label: 'Running ML classifier' },
  { id: 'threat_intel', label: 'Threat intelligence' },
  { id: 'correlation', label: 'Correlating evidence' },
  { id: 'scoring', label: 'Calculating risk' },
  { id: 'persist', label: 'Saving investigation' },
];

/** Shows backend stages exactly as they report in; no simulated progress. */
export function AnalysisProgress({ stages, failed }: { stages: StageTiming[]; failed?: boolean }) {
  const done = new Map(stages.map((s) => [s.id, s]));
  const currentIndex = STAGE_ORDER.findIndex((s) => !done.has(s.id));
  return (
    <div aria-live="polite">
      <p className="mb-3 text-[13px] font-semibold">
        {failed
          ? 'Analysis stopped'
          : currentIndex === -1
            ? 'Analysis complete'
            : 'Analysis in progress'}
      </p>
      <ol className="space-y-0.5">
        {STAGE_ORDER.map((stage, i) => {
          const result = done.get(stage.id);
          const active = !result && i === currentIndex && !failed;
          const Icon = result
            ? result.status === 'skipped'
              ? Minus
              : result.status === 'failed'
                ? X
                : Check
            : active
              ? Loader2
              : failed && i === currentIndex
                ? X
                : Circle;
          return (
            <li
              key={stage.id}
              className={cx(
                'grid grid-cols-[18px_1fr_auto] items-center gap-2.5 py-1 text-[13px]',
                !result && !active && 'text-faint',
              )}
            >
              <Icon
                size={14}
                className={cx(
                  active && 'animate-spin text-accent',
                  result?.status === 'done' && 'text-safe',
                  result?.status === 'skipped' && 'text-faint',
                  (result?.status === 'failed' || (failed && i === currentIndex)) &&
                    'text-critical',
                )}
              />
              <span className={cx('min-w-0', result && 'text-text')}>
                {result?.label ?? stage.label}
                {result?.detail && (
                  <span className="ml-2 text-[12px] text-muted">{result.detail}</span>
                )}
              </span>
              <span className="text-[11.5px] tabular-nums text-faint">
                {result ? `${result.durationMs.toFixed(result.durationMs < 10 ? 1 : 0)} ms` : ''}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
