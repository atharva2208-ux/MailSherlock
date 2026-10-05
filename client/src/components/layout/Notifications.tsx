import { Bell } from 'lucide-react';
import { useState } from 'react';
import { formatRelative } from '../../utils/format';
import { useToast } from '../common/Toast';
import { usePopover } from './usePopover';

const COLOR = { success: 'var(--safe)', warning: 'var(--medium)', error: 'var(--critical)' };

export function Notifications() {
  const { history, clearHistory } = useToast();
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useState(0);
  const ref = usePopover(open, () => setOpen(false));
  const unread = history.filter((h) => h.at > seen).length;

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => {
          setOpen((o) => !o);
          setSeen(Date.now());
        }}
        aria-label={`Notifications${unread ? ` (${unread} new)` : ''}`}
        aria-expanded={open}
        className="relative flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-raised hover:text-text"
      >
        <Bell size={16} />
        {unread > 0 && (
          <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-accent" />
        )}
      </button>
      {open && (
        <div
          role="dialog"
          aria-label="Notifications"
          className="absolute right-0 z-40 mt-2 w-80 rounded-lg border border-line-strong bg-surface shadow-[var(--shadow)]"
        >
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <p className="text-[13px] font-semibold">Activity this session</p>
            {history.length > 0 && (
              <button
                type="button"
                className="text-[12px] text-muted hover:text-text"
                onClick={clearHistory}
              >
                Clear
              </button>
            )}
          </div>
          {history.length === 0 ? (
            <p className="px-3 py-6 text-center text-[12.5px] text-muted">
              Analyses, exports and errors will appear here.
            </p>
          ) : (
            <ul className="max-h-80 overflow-y-auto py-1">
              {history.map((item) => (
                <li key={item.id} className="flex gap-2.5 px-3 py-2">
                  <span
                    aria-hidden
                    className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                    style={{ background: COLOR[item.tone] }}
                  />
                  <div className="min-w-0">
                    <p className="text-[13px]">{item.title}</p>
                    {item.message && (
                      <p className="truncate text-[12px] text-muted">{item.message}</p>
                    )}
                    <p className="text-[11.5px] text-faint">
                      {formatRelative(new Date(item.at).toISOString())}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
