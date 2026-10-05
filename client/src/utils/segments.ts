import type { Finding } from '../types';

export interface Segment {
  text: string;
  findingIds: string[];
}

/** Split text into runs, each tagged with the findings whose evidence spans cover it. */
export function segmentText(text: string, findings: Finding[]): Segment[] {
  const cuts = new Set([0, text.length]);
  const spans = findings.flatMap((f) =>
    (f.spans ?? [])
      .filter((s) => s.end <= text.length && s.start < s.end)
      .map((s) => ({ ...s, id: f.id })),
  );
  for (const span of spans) {
    cuts.add(span.start);
    cuts.add(span.end);
  }
  const points = [...cuts].sort((a, b) => a - b);
  const segments: Segment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const start = points[i]!;
    const end = points[i + 1]!;
    const ids = [
      ...new Set(spans.filter((s) => s.start <= start && s.end >= end).map((s) => s.id)),
    ];
    const last = segments.at(-1);
    if (last && !ids.length && !last.findingIds.length) last.text += text.slice(start, end);
    else segments.push({ text: text.slice(start, end), findingIds: ids });
  }
  return segments;
}
