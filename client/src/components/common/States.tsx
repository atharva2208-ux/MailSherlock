import { AlertOctagon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cx } from '../../utils/format';

export function EmptyState({
  icon,
  title,
  children,
  action,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-3 px-2 py-10 sm:items-center sm:text-center">
      {icon && <div className="text-faint">{icon}</div>}
      <div>
        <p className="text-[15px] font-semibold text-text">{title}</p>
        {children && <div className="mt-1 max-w-md text-[13px] text-muted">{children}</div>}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  action,
}: {
  title?: string;
  message: string;
  action?: ReactNode;
}) {
  return (
    <div
      role="alert"
      className="flex gap-3 rounded-lg border border-[color-mix(in_srgb,var(--critical)_40%,transparent)] bg-[color-mix(in_srgb,var(--critical)_7%,transparent)] p-4"
    >
      <AlertOctagon size={18} className="mt-0.5 shrink-0 text-critical" />
      <div className="min-w-0">
        <p className="font-semibold text-text">{title}</p>
        <p className="mt-0.5 text-[13px] text-muted">{message}</p>
        {action && <div className="mt-3">{action}</div>}
      </div>
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cx('animate-pulse rounded bg-raised', className)} />;
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="whitespace-nowrap rounded border border-line-strong bg-raised px-1.5 py-px text-[11px] text-muted">
      {children}
    </kbd>
  );
}
