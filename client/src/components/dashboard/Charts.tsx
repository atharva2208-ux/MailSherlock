import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { CATEGORY_LABEL, LEVEL_COLOR, RISK_LABEL } from '../../constants/severity';
import type { DashboardStats, RiskLevel } from '../../types';
import { LevelDot } from '../common/Badge';

const tooltipStyle = {
  contentStyle: {
    background: 'var(--surface)',
    border: '1px solid var(--line-strong)',
    borderRadius: 6,
    fontSize: 12.5,
    color: 'var(--text)',
  },
  labelStyle: { color: 'var(--muted)' },
  cursor: { fill: 'var(--raised)' },
};
const axis = { stroke: 'var(--faint)', fontSize: 11.5, tickLine: false, axisLine: false } as const;

export function HistoryChart({ history }: { history: DashboardStats['history'] }) {
  const data = history.map((d) => ({
    ...d,
    day: new Date(`${d.date}T00:00:00`).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
    }),
  }));
  return (
    <div
      className="h-56"
      role="img"
      aria-label="Investigations per day over the last 30 days, by classification"
    >
      <ResponsiveContainer>
        <BarChart
          data={data}
          margin={{ top: 4, right: 4, bottom: 0, left: -24 }}
          barCategoryGap={3}
        >
          <CartesianGrid vertical={false} stroke="var(--line)" />
          <XAxis dataKey="day" {...axis} interval={4} />
          <YAxis allowDecimals={false} {...axis} />
          <Tooltip {...tooltipStyle} />
          <Bar dataKey="phishing" name="Phishing" stackId="a" fill="var(--critical)" />
          <Bar dataKey="suspicious" name="Suspicious" stackId="a" fill="var(--medium)" />
          <Bar
            dataKey="legitimate"
            name="Legitimate"
            stackId="a"
            fill="var(--safe)"
            radius={[2, 2, 0, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function RiskDistribution({
  distribution,
}: {
  distribution: DashboardStats['riskDistribution'];
}) {
  const levels: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'safe'];
  const total = Math.max(
    1,
    levels.reduce((s, l) => s + distribution[l], 0),
  );
  return (
    <div>
      <div
        className="flex h-3 overflow-hidden rounded-[3px]"
        role="img"
        aria-label="Share of investigations by risk level"
      >
        {levels.map((l) =>
          distribution[l] ? (
            <div
              key={l}
              style={{ width: `${(distribution[l] / total) * 100}%`, background: LEVEL_COLOR[l] }}
            />
          ) : null,
        )}
      </div>
      <ul className="mt-3 space-y-1.5 text-[13px]">
        {levels.map((l) => (
          <li key={l} className="flex items-center justify-between">
            <LevelDot level={l} label={RISK_LABEL[l]} />
            <span className="tabular-nums text-muted">
              {distribution[l]}{' '}
              <span className="text-faint">· {Math.round((distribution[l] / total) * 100)}%</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function CategoryBars({ categories }: { categories: DashboardStats['categories'] }) {
  const max = Math.max(1, ...categories.map((c) => c.count));
  if (!categories.length)
    return <p className="text-[13px] text-muted">No findings recorded yet.</p>;
  return (
    <ul className="space-y-2">
      {categories.map((c) => (
        <li
          key={c.category}
          className="grid grid-cols-[120px_1fr_36px] items-center gap-3 text-[13px]"
        >
          <span className="truncate">{CATEGORY_LABEL[c.category] ?? c.category}</span>
          <span className="h-2 rounded-full bg-raised">
            <span
              className="block h-full rounded-full bg-accent"
              style={{ width: `${(c.count / max) * 100}%` }}
            />
          </span>
          <span className="text-right tabular-nums text-muted">{c.count}</span>
        </li>
      ))}
    </ul>
  );
}
