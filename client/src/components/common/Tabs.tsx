import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { cx } from '../../utils/format';

export interface TabItem {
  id: string;
  label: string;
  count?: number;
  tone?: string;
}

/** WAI-ARIA tabs with arrow-key navigation. */
export function Tabs({
  tabs,
  active,
  onChange,
  children,
  label,
}: {
  tabs: TabItem[];
  active: string;
  onChange: (id: string) => void;
  children: ReactNode;
  label: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (event: KeyboardEvent, index: number) => {
    const delta = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (index + delta + tabs.length) % tabs.length;
    refs.current[next]?.focus();
    onChange(tabs[next]!.id);
  };
  return (
    <div>
      <div
        role="tablist"
        aria-label={label}
        className="no-print flex gap-0.5 overflow-x-auto border-b border-line"
      >
        {tabs.map((tab, i) => (
          <button
            key={tab.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={active === tab.id}
            aria-controls={`panel-${tab.id}`}
            tabIndex={active === tab.id ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={(e) => onKey(e, i)}
            className={cx(
              '-mb-px flex h-10 shrink-0 items-center gap-1.5 border-b-2 px-3 text-[13px] transition-colors',
              active === tab.id
                ? 'border-accent font-medium text-text'
                : 'border-transparent text-muted hover:text-text',
            )}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span
                className="rounded bg-raised px-1.5 text-[11px] tabular-nums text-muted"
                style={tab.tone ? { color: tab.tone } : undefined}
              >
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`panel-${active}`}
        aria-labelledby={`tab-${active}`}
        className="pt-4"
      >
        {children}
      </div>
    </div>
  );
}
