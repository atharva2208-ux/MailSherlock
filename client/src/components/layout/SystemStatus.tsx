import { Activity } from 'lucide-react';
import { useState } from 'react';
import { useHealth } from '../../hooks/useHealth';
import type { ComponentHealth } from '../../types';
import { cx } from '../../utils/format';
import { usePopover } from './usePopover';

const DOT: Record<ComponentHealth['status'], string> = {
  up: 'var(--safe)',
  down: 'var(--critical)',
  degraded: 'var(--medium)',
  not_configured: 'var(--faint)',
};

export function StatusLine({ name, health }: { name: string; health: ComponentHealth }) {
  return (
    <li className="flex items-start gap-2.5 py-1.5">
      <span
        aria-hidden
        className={cx(
          'mt-1.5 h-2 w-2 shrink-0 rounded-full',
          health.status === 'not_configured' && 'border border-faint bg-transparent',
        )}
        style={health.status === 'not_configured' ? undefined : { background: DOT[health.status] }}
      />
      <div className="min-w-0">
        <p className="text-[13px] text-text">{name}</p>
        <p className="text-[12px] text-muted">
          {health.detail}
          {health.latencyMs !== undefined && ` · ${health.latencyMs} ms`}
        </p>
      </div>
    </li>
  );
}

export function SystemStatus() {
  const { data, isError } = useHealth();
  const [open, setOpen] = useState(false);
  const ref = usePopover(open, () => setOpen(false));
  const mlUp = data?.components.ml.status === 'up';
  const label = isError
    ? 'API offline'
    : !data
      ? 'Checking…'
      : mlUp
        ? 'All systems online'
        : 'Rule engine only';
  const color = isError
    ? 'var(--critical)'
    : !data
      ? 'var(--faint)'
      : mlUp
        ? 'var(--safe)'
        : 'var(--medium)';

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="dialog"
        className="flex h-8 items-center gap-2 rounded-md px-2.5 text-[12.5px] text-muted hover:bg-raised hover:text-text"
      >
        <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: color }} />
        <span className="hidden whitespace-nowrap xl:inline">{label}</span>
        <Activity size={15} className="xl:hidden" />
      </button>
      {open && (
        <div
          role="dialog"
          aria-label="System status"
          className="absolute right-0 z-40 mt-2 w-80 rounded-lg border border-line-strong bg-surface p-3 shadow-[var(--shadow)]"
        >
          <p className="mb-1 text-[13px] font-semibold">System status</p>
          {isError && <p className="text-[12.5px] text-critical">The API is not responding.</p>}
          {data && (
            <ul>
              <StatusLine name="Analysis engine" health={data.components.api} />
              <StatusLine name="ML classifier" health={data.components.ml} />
              <StatusLine name="Database" health={data.components.database} />
              <StatusLine name="Storage" health={data.components.storage} />
              {Object.entries(data.components.threatIntel).map(([name, health]) => (
                <StatusLine key={name} name={name} health={health} />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
