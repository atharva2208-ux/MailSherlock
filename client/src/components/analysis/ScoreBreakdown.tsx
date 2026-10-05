import type { RiskAssessment } from '../../types';

const KIND_LABEL = {
  rule: 'Rule evidence',
  ml: 'Machine learning',
  correlation: 'Correlation',
  trust: 'Context',
} as const;
const KIND_COLOR = {
  rule: 'var(--high)',
  ml: 'var(--accent)',
  correlation: 'var(--medium)',
  trust: 'var(--safe)',
} as const;

/** How the score was built, contribution by contribution. */
export function ScoreBreakdown({ risk }: { risk: RiskAssessment }) {
  const max = Math.max(10, ...risk.contributions.map((c) => Math.abs(c.points)));
  return (
    <div>
      <ul className="space-y-2.5">
        {risk.contributions.map((c, i) => (
          <li key={`${c.label}-${i}`} className="text-[13px]">
            <div className="flex items-baseline justify-between gap-3">
              <span className="min-w-0 truncate">
                {c.label} <span className="text-[11.5px] text-faint">{KIND_LABEL[c.kind]}</span>
              </span>
              <span
                className="tabular-nums font-medium"
                style={{ color: c.points < 0 ? 'var(--safe)' : undefined }}
              >
                {c.points > 0 ? '+' : ''}
                {c.points}
              </span>
            </div>
            <div className="mt-1 h-1.5 rounded-full bg-raised">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${(Math.abs(c.points) / max) * 100}%`,
                  background: c.points < 0 ? 'var(--safe)' : KIND_COLOR[c.kind],
                }}
              />
            </div>
            {c.detail && <p className="mt-1 text-[12px] text-muted">{c.detail}</p>}
          </li>
        ))}
        {!risk.contributions.length && (
          <li className="text-[13px] text-muted">No evidence contributed to the score.</li>
        )}
      </ul>
      <p className="mt-4 border-t border-line pt-3 text-[12px] text-muted">
        {risk.rawPoints} raw points are mapped onto 0–100 with a saturating curve, so additional
        independent evidence always raises the score but never past 100.
      </p>
    </div>
  );
}
