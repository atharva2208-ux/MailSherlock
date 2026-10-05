import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { api } from '../../services/api';
import { Button } from '../common/Button';
import { CopyButton } from '../common/CopyButton';
import { ErrorState, Skeleton } from '../common/States';

const MAX_LINES = 4000;

type LineKind = 'header' | 'continuation' | 'boundary' | 'body';

function classify(lines: string[]): LineKind[] {
  const kinds: LineKind[] = [];
  let inHeaders = true;
  for (const line of lines) {
    if (/^--[\w'()+,./:=?-]{1,70}(--)?\s*$/.test(line)) {
      kinds.push('boundary');
      inHeaders = true; // each MIME part starts with its own headers
      continue;
    }
    if (inHeaders && line.trim() === '') {
      inHeaders = false;
      kinds.push('body');
      continue;
    }
    if (inHeaders && /^[\t ]/.test(line)) kinds.push('continuation');
    else if (inHeaders && /^[!-9;-~]+:/.test(line)) kinds.push('header');
    else {
      inHeaders = false;
      kinds.push('body');
    }
  }
  return kinds;
}

/** Forensic view of the original message with header names, folding and MIME boundaries distinguished. */
export function RawSourceViewer({ analysisId }: { analysisId: string }) {
  const { data, error, isLoading } = useQuery({
    queryKey: ['raw', analysisId],
    queryFn: () => api.getRaw(analysisId),
    staleTime: Infinity,
  });
  const [headersOnly, setHeadersOnly] = useState(false);
  const lines = useMemo(() => (data ?? '').split(/\r?\n/), [data]);
  const kinds = useMemo(() => classify(lines), [lines]);

  if (isLoading) return <Skeleton className="h-96" />;
  if (error)
    return <ErrorState title="Raw source unavailable" message={(error as Error).message} />;

  const firstBody = kinds.indexOf('body');
  const shown = headersOnly
    ? lines.slice(0, firstBody === -1 ? lines.length : firstBody)
    : lines.slice(0, MAX_LINES);

  return (
    <div className="rounded-lg border border-line bg-surface">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2">
        <p className="text-[12.5px] text-muted">
          {lines.length.toLocaleString()} lines · <span className="text-accent">header</span> ·{' '}
          <span className="text-medium">MIME boundary</span> · shown as inert text
        </p>
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant={headersOnly ? 'secondary' : 'ghost'}
            aria-pressed={headersOnly}
            onClick={() => setHeadersOnly((h) => !h)}
          >
            Headers only
          </Button>
          <CopyButton value={data ?? ''} label="Copy raw source" />
        </div>
      </div>
      <pre
        className="max-h-[70vh] overflow-auto py-2 font-mono text-[12px] leading-[1.6]"
        aria-label="Raw email source"
      >
        {shown.map((line, i) => {
          const kind = kinds[i];
          const header = kind === 'header' ? /^([^:]+:)(.*)$/.exec(line) : null;
          return (
            <div key={i} className="grid grid-cols-[52px_1fr] hover:bg-raised">
              <span className="pr-3 text-right text-faint select-none">{i + 1}</span>
              <span className="pr-4 break-all whitespace-pre-wrap">
                {header ? (
                  <>
                    <span className="text-accent">{header[1]}</span>
                    {header[2]}
                  </>
                ) : (
                  <span
                    className={
                      kind === 'boundary'
                        ? 'text-medium'
                        : kind === 'continuation'
                          ? 'text-muted'
                          : undefined
                    }
                  >
                    {line || ' '}
                  </span>
                )}
              </span>
            </div>
          );
        })}
      </pre>
      {!headersOnly && lines.length > MAX_LINES && (
        <p className="border-t border-line px-4 py-2 text-[12px] text-muted">
          Showing the first {MAX_LINES.toLocaleString()} lines. Copy the source to see everything.
        </p>
      )}
    </div>
  );
}
