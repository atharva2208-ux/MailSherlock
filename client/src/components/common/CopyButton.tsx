import { Check, Copy } from 'lucide-react';
import { useCopy } from '../../hooks/useCopy';

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const { copied, copy } = useCopy();
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        void copy(value);
      }}
      className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded text-faint hover:bg-raised hover:text-text"
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? <Check size={13} className="text-safe" /> : <Copy size={13} />}
    </button>
  );
}
