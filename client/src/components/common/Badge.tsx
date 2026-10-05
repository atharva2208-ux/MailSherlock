import {
  CLASSIFICATION_COLOR,
  CLASSIFICATION_LABEL,
  LEVEL_COLOR,
  RISK_LABEL,
  SEVERITY_LABEL,
} from '../../constants/severity';
import type { Classification, RiskLevel, Severity } from '../../types';
import { cx } from '../../utils/format';

const tint = (color: string, amount = 14) => `color-mix(in srgb, ${color} ${amount}%, transparent)`;

/** Severity chip: tinted background + coloured text, used wherever a level is the point of the cell. */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity | RiskLevel;
  className?: string;
}) {
  const color = LEVEL_COLOR[severity];
  const label =
    severity in SEVERITY_LABEL
      ? SEVERITY_LABEL[severity as Severity]
      : RISK_LABEL[severity as RiskLevel];
  return (
    <span
      className={cx(
        'inline-flex h-5 w-fit items-center self-start justify-self-start rounded px-1.5 text-[11.5px] font-semibold leading-none whitespace-nowrap',
        className,
      )}
      style={{ color, background: tint(color) }}
    >
      {label}
    </span>
  );
}

/** Compact square marker + label, for dense lists where a chip would be too heavy. */
export function LevelDot({
  level,
  label,
}: {
  level: Severity | RiskLevel | 'none';
  label?: string;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span
        aria-hidden
        className="h-2 w-2 shrink-0 rounded-[2px]"
        style={{ background: LEVEL_COLOR[level] }}
      />
      {label !== undefined && <span>{label}</span>}
    </span>
  );
}

export function ClassificationTag({ value }: { value: Classification }) {
  const color = CLASSIFICATION_COLOR[value];
  return (
    <span
      className="inline-flex items-center gap-1.5 font-medium whitespace-nowrap"
      style={{ color }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {CLASSIFICATION_LABEL[value]}
    </span>
  );
}

export function SourceTag({ source }: { source: 'rule' | 'threat_intel' | 'ml' | 'analyst' }) {
  const labels = { rule: 'Rule', threat_intel: 'Threat intel', ml: 'ML', analyst: 'Analyst' };
  return (
    <span className="rounded border border-line px-1.5 py-px text-[11px] text-muted">
      {labels[source]}
    </span>
  );
}
