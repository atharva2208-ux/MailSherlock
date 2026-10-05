import { AlertTriangle, ArrowDown, Inbox, Send, Server } from 'lucide-react';
import type { ReceivedHop } from '../../types';
import { cx, formatDateTime } from '../../utils/format';

function delay(seconds: number | undefined) {
  if (seconds === undefined) return null;
  const abs = Math.abs(seconds);
  const text =
    abs < 60
      ? `${abs}s`
      : abs < 3600
        ? `${Math.round(abs / 60)} min`
        : `${(abs / 3600).toFixed(1)} h`;
  return seconds < 0 ? `−${text}` : `+${text}`;
}

/** Relay path from origin to recipient, with anomalous hops highlighted. */
export function ReceivedChain({ hops }: { hops: ReceivedHop[] }) {
  if (!hops.length)
    return (
      <p className="text-[13px] text-muted">
        No Received headers - the routing path cannot be reconstructed.
      </p>
    );
  return (
    <ol aria-label="Mail routing path, origin first" className="space-y-0">
      {hops.map((hop, i) => {
        const Icon = i === 0 ? Send : i === hops.length - 1 ? Inbox : Server;
        const flagged = hop.flags.filter(
          (f) => f !== 'missing or unparseable timestamp' || hops.length < 3,
        );
        return (
          <li key={hop.index}>
            {i > 0 && (
              <div className="flex items-center gap-2 py-1 pl-[13px] text-[11.5px] text-faint">
                <ArrowDown size={13} />
                {delay(hop.delaySeconds)}
              </div>
            )}
            <details
              className={cx(
                'group rounded-md border bg-surface',
                flagged.length
                  ? 'border-[color-mix(in_srgb,var(--high)_55%,transparent)]'
                  : 'border-line',
              )}
            >
              <summary className="grid cursor-pointer list-none grid-cols-[28px_minmax(0,1fr)_auto] items-center gap-3 px-3 py-2.5">
                <Icon size={16} className={flagged.length ? 'text-high' : 'text-muted'} />
                <span className="min-w-0">
                  <span className="block truncate text-[13px]">
                    <span className="text-muted">{i === 0 ? 'Origin ' : `Hop ${hop.index} `}</span>
                    <span className="font-mono text-[12.5px]">{hop.from ?? 'unknown sender'}</span>
                    <span className="text-muted"> → </span>
                    <span className="font-mono text-[12.5px]">{hop.by ?? 'unknown'}</span>
                  </span>
                  <span className="block text-[12px] text-muted">
                    {hop.timestamp ? formatDateTime(hop.timestamp) : 'no timestamp'}
                    {hop.with && ` · ${hop.with}`}
                    {hop.fromIp && ` · ${hop.fromIp}`}
                  </span>
                </span>
                {flagged.length > 0 && (
                  <span className="flex items-center gap-1 text-[12px] text-high">
                    <AlertTriangle size={13} />
                    {flagged.length}
                  </span>
                )}
              </summary>
              <div className="border-t border-line px-3 py-2.5 pl-[52px]">
                {flagged.map((f) => (
                  <p key={f} className="text-[12.5px] text-high">
                    {f}
                  </p>
                ))}
                <pre className="mt-1 font-mono text-[11.5px] break-all whitespace-pre-wrap text-muted">
                  {hop.raw}
                </pre>
              </div>
            </details>
          </li>
        );
      })}
    </ol>
  );
}
