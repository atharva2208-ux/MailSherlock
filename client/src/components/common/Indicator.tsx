import { defang } from '../../utils/format';
import { CopyButton } from './CopyButton';

/** A URL/domain shown defanged (never clickable) with a copy action for the original value. */
export function Indicator({ value, className }: { value: string; className?: string }) {
  return (
    <span className={`inline-flex min-w-0 max-w-full items-center gap-1 ${className ?? ''}`}>
      <code className="min-w-0 truncate font-mono text-[12.5px] text-text" title={value}>
        {defang(value)}
      </code>
      <CopyButton value={value} label="Copy original value" />
    </span>
  );
}
