import { useMemo } from 'react';
import type { Finding } from '../../types';
import { segmentText } from '../../utils/segments';

export function HighlightedContent({
  text,
  findings,
  activeId,
  onSelect,
}: {
  text: string;
  findings: Finding[];
  activeId?: string | null;
  onSelect: (id: string) => void;
}) {
  const segments = useMemo(() => segmentText(text, findings), [text, findings]);
  const titles = useMemo(() => new Map(findings.map((f) => [f.id, f.title])), [findings]);
  return (
    <div className="font-sans text-[13.5px] leading-[1.7] break-words whitespace-pre-wrap">
      {segments.map((segment, i) =>
        segment.findingIds.length ? (
          <mark
            key={i}
            role="button"
            tabIndex={0}
            data-active={activeId ? segment.findingIds.includes(activeId) : false}
            className="mark-evidence text-inherit"
            title={segment.findingIds.map((id) => titles.get(id)).join(' · ')}
            aria-label={`Evidence for: ${segment.findingIds.map((id) => titles.get(id)).join(', ')}`}
            onClick={() => onSelect(segment.findingIds[0]!)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onSelect(segment.findingIds[0]!);
              }
            }}
          >
            {segment.text}
          </mark>
        ) : (
          <span key={i}>{segment.text}</span>
        ),
      )}
    </div>
  );
}
