import { useEffect, useMemo, useRef, useState } from 'react';
import {
  LEVEL_COLOR,
  SCORE_GROUP_LABEL,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
} from '../../constants/severity';
import type { Finding, RiskAssessment, Severity } from '../../types';
import { cx } from '../../utils/format';
import { EmptyState } from '../common/States';
import { FindingCard } from './FindingCard';

export function FindingsPanel({
  findings,
  risk,
  focusId,
}: {
  findings: Finding[];
  risk?: RiskAssessment;
  focusId?: string | null;
}) {
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set(focusId ? [focusId] : []));
  const refs = useRef(new Map<string, HTMLDivElement>());

  const sorted = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
          b.confidence - a.confidence,
      ),
    [findings],
  );
  const visible = filter === 'all' ? sorted : sorted.filter((f) => f.severity === filter);
  const contributionFor = (f: Finding) => {
    const label = SCORE_GROUP_LABEL[f.scoreGroup];
    const c = risk?.contributions.find((x) => x.label === label);
    return c ? `${label} (+${c.points})` : undefined;
  };

  // The parent remounts this panel per focused finding, so the initial state
  // already has it open; the effect only scrolls it into view.
  useEffect(() => {
    if (focusId)
      requestAnimationFrame(() =>
        refs.current.get(focusId)?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
  }, [focusId]);

  if (!findings.length) {
    return (
      <EmptyState title="No findings">
        None of the detectors found indicators of phishing in this message.
      </EmptyState>
    );
  }

  return (
    <div className="rounded-lg border border-line bg-surface">
      <div
        role="toolbar"
        aria-label="Filter findings by severity"
        className="flex flex-wrap items-center gap-1 border-b border-line px-3 py-2"
      >
        {(['all', ...SEVERITY_ORDER] as const).map((level) => {
          const count =
            level === 'all' ? findings.length : findings.filter((f) => f.severity === level).length;
          if (level !== 'all' && !count) return null;
          return (
            <button
              key={level}
              type="button"
              aria-pressed={filter === level}
              onClick={() => setFilter(level)}
              className={cx(
                'flex h-7 items-center gap-1.5 rounded-md px-2.5 text-[12.5px]',
                filter === level ? 'bg-raised text-text' : 'text-muted hover:text-text',
              )}
            >
              {level !== 'all' && (
                <span
                  aria-hidden
                  className="h-2 w-2 rounded-[2px]"
                  style={{ background: LEVEL_COLOR[level] }}
                />
              )}
              {level === 'all' ? 'All' : SEVERITY_LABEL[level]}
              <span className="tabular-nums text-faint">{count}</span>
            </button>
          );
        })}
        <button
          type="button"
          className="ml-auto text-[12px] text-muted hover:text-text"
          onClick={() => setOpenIds(openIds.size ? new Set() : new Set(visible.map((f) => f.id)))}
        >
          {openIds.size ? 'Collapse all' : 'Expand all'}
        </button>
      </div>
      <div>
        {visible.map((finding) => (
          <FindingCard
            key={finding.id}
            ref={(el) => {
              if (el) refs.current.set(finding.id, el);
            }}
            finding={finding}
            open={openIds.has(finding.id)}
            contribution={contributionFor(finding)}
            onToggle={() =>
              setOpenIds((s) => {
                const next = new Set(s);
                if (next.has(finding.id)) next.delete(finding.id);
                else next.add(finding.id);
                return next;
              })
            }
          />
        ))}
      </div>
    </div>
  );
}
