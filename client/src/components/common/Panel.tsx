import type { ReactNode } from 'react';
import { cx } from '../../utils/format';

/** The one container style: a surface with an optional header row. Nested sections use dividers, not more boxes. */
export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
  id,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  id?: string;
}) {
  return (
    <section
      id={id}
      className={cx('rounded-lg border border-line bg-surface', className)}
      aria-label={typeof title === 'string' ? title : undefined}
    >
      {(title || actions) && (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-line px-4 py-2">
          <div className="min-w-0">
            {title && <h2 className="text-[13.5px] font-semibold text-text">{title}</h2>}
            {description && <p className="text-[12.5px] text-muted">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx('p-4', bodyClassName)}>{children}</div>
    </section>
  );
}

export function Field({
  label,
  children,
  mono,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[minmax(96px,140px)_1fr] gap-3 py-1.5 text-[13px]">
      <dt className="text-muted">{label}</dt>
      <dd className={cx('min-w-0 break-words text-text', mono && 'font-mono text-[12.5px]')}>
        {children}
      </dd>
    </div>
  );
}
