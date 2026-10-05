import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from 'react';
import { forwardRef } from 'react';
import { cx } from '../../utils/format';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-accent text-[#120d2e] hover:bg-accent-strong font-semibold',
  secondary: 'border border-line-strong bg-raised text-text hover:border-faint',
  ghost: 'text-muted hover:bg-raised hover:text-text',
  danger:
    'border border-line-strong text-critical hover:bg-[color-mix(in_srgb,var(--critical)_12%,transparent)]',
};

const base =
  'inline-flex items-center justify-center gap-1.5 rounded-md transition-colors disabled:cursor-not-allowed disabled:opacity-50 active:translate-y-px';
const sizes = { sm: 'h-7 px-2.5 text-[12.5px]', md: 'h-9 px-3.5 text-[13.5px]' };

/** An anchor styled as a button, for downloads and navigation (never nest a button inside a link). */
export function LinkButton({
  variant = 'secondary',
  size = 'md',
  icon,
  className,
  children,
  ...props
}: AnchorHTMLAttributes<HTMLAnchorElement> & {
  variant?: Variant;
  size?: 'sm' | 'md';
  icon?: ReactNode;
}) {
  return (
    <a className={cx(base, sizes[size], VARIANTS[variant], className)} {...props}>
      {icon}
      {children}
    </a>
  );
}

export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: Variant;
    icon?: ReactNode;
    size?: 'sm' | 'md';
  }
>(function Button(
  { variant = 'secondary', icon, size = 'md', className, children, type = 'button', ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cx(base, sizes[size], VARIANTS[variant], className)}
      {...props}
    >
      {icon}
      {children}
    </button>
  );
});
