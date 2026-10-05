import { useMemo, useState } from 'react';
import { LEVEL_COLOR, SEVERITY_ORDER } from '../../constants/severity';
import type { AnalysisResult, Severity } from '../../types';

interface Node {
  id: string;
  label: string;
  sub: string;
  relation: string;
  level: Severity | 'none';
  tab?: string;
}

const orgOf = (domain: string) => domain.split('.').slice(-2).join('.');
const worst = (levels: (Severity | 'none')[]): Severity | 'none' =>
  SEVERITY_ORDER.find((s) => levels.includes(s)) ?? 'none';

/**
 * Relationships between the sender identity and the infrastructure the message
 * touches. Only relationships that exist in the evidence are drawn, and the
 * graph is omitted when there is nothing to relate.
 */
export function InvestigationGraph({
  analysis,
  onNavigate,
}: {
  analysis: AnalysisResult;
  onNavigate?: (tab: string) => void;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const from = analysis.metadata.from;

  const nodes = useMemo<Node[]>(() => {
    if (!from) return [];
    const fromOrg = orgOf(from.domain);
    const list: Node[] = [];
    for (const r of analysis.metadata.replyTo ?? []) {
      if (orgOf(r.domain) !== fromOrg)
        list.push({
          id: `reply-${r.address}`,
          label: r.domain,
          sub: r.address,
          relation: 'replies go to',
          level: 'high',
          tab: 'headers',
        });
    }
    const rp = analysis.metadata.returnPath?.split('@').pop();
    if (rp && orgOf(rp) !== fromOrg)
      list.push({
        id: 'return',
        label: rp,
        sub: 'Return-Path',
        relation: 'bounces to',
        level: analysis.authentication.dmarc.state === 'pass' ? 'info' : 'low',
        tab: 'headers',
      });
    const dkim = analysis.authentication.dkim.domain;
    if (dkim && orgOf(dkim) !== fromOrg && analysis.authentication.dkim.state !== 'not_present')
      list.push({
        id: 'dkim',
        label: dkim,
        sub: `DKIM ${analysis.authentication.dkim.state}`,
        relation: 'signed by',
        level: 'low',
        tab: 'authentication',
      });
    const origin = analysis.received.find((h) => h.fromIp);
    if (origin?.fromIp)
      list.push({
        id: 'ip',
        label: origin.fromIp,
        sub: 'origin server',
        relation: 'sent from',
        level: origin.flags.length ? 'low' : 'none',
        tab: 'headers',
      });
    const domains = new Map<string, { level: Severity | 'none'; count: number }>();
    for (const u of analysis.urls.filter((x) => x.source !== 'image' && x.registrableDomain)) {
      const entry = domains.get(u.registrableDomain) ?? { level: 'none' as const, count: 0 };
      domains.set(u.registrableDomain, {
        level: worst([entry.level, u.risk]),
        count: entry.count + 1,
      });
    }
    [...domains.entries()]
      .sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a[1].level as Severity) -
          SEVERITY_ORDER.indexOf(b[1].level as Severity),
      )
      .slice(0, 6)
      .forEach(([domain, info]) =>
        list.push({
          id: `link-${domain}`,
          label: domain,
          sub: `${info.count} link${info.count === 1 ? '' : 's'}`,
          relation: domain === fromOrg ? 'links to (own domain)' : 'links to',
          level: info.level,
          tab: 'urls',
        }),
      );
    return list;
  }, [analysis, from]);

  if (!from || nodes.length < 2) return null;

  const rowH = 46;
  const height = Math.max(nodes.length * rowH + 10, 120);
  const centerY = height / 2;
  const fromLevel = worst(
    analysis.findings
      .filter((f) => ['impersonation', 'domain', 'authentication'].includes(f.category))
      .map((f) => f.severity),
  );

  return (
    <figure>
      <svg
        viewBox={`0 0 640 ${height}`}
        className="w-full"
        role="img"
        aria-label="Relationships between the sender and the infrastructure in this message"
      >
        {nodes.map((node, i) => {
          const y = 10 + i * rowH + rowH / 2 - 5;
          const active = hover === node.id;
          return (
            <g key={node.id}>
              <path
                d={`M 230 ${centerY} C 300 ${centerY}, 320 ${y}, 380 ${y}`}
                fill="none"
                stroke={active ? 'var(--accent)' : 'var(--line-strong)'}
                strokeWidth={active ? 2 : 1.3}
              />
              <text x={384} y={y - 12} fill="var(--faint)" fontSize="10.5">
                {node.relation}
              </text>
              <g
                role={onNavigate && node.tab ? 'button' : undefined}
                tabIndex={onNavigate && node.tab ? 0 : undefined}
                className={onNavigate && node.tab ? 'cursor-pointer' : undefined}
                onMouseEnter={() => setHover(node.id)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(node.id)}
                onBlur={() => setHover(null)}
                onClick={() => node.tab && onNavigate?.(node.tab)}
                onKeyDown={(e) => e.key === 'Enter' && node.tab && onNavigate?.(node.tab)}
              >
                <rect
                  x={380}
                  y={y - 6}
                  width={256}
                  height={30}
                  rx={5}
                  fill="var(--raised)"
                  stroke={active ? 'var(--accent)' : 'var(--line)'}
                />
                <rect
                  x={380}
                  y={y - 6}
                  width={4}
                  height={30}
                  rx={2}
                  fill={LEVEL_COLOR[node.level]}
                />
                <text
                  x={392}
                  y={y + 9}
                  fill="var(--text)"
                  fontSize="12"
                  fontFamily="var(--font-mono)"
                >
                  {node.label.length > 26 ? `${node.label.slice(0, 25)}…` : node.label}
                </text>
                <text x={628} y={y + 9} fill="var(--muted)" fontSize="10.5" textAnchor="end">
                  {node.sub.length > 14 ? '' : node.sub}
                </text>
              </g>
            </g>
          );
        })}
        <rect
          x={10}
          y={centerY - 26}
          width={220}
          height={52}
          rx={6}
          fill="var(--raised)"
          stroke="var(--line-strong)"
        />
        <rect x={10} y={centerY - 26} width={4} height={52} rx={2} fill={LEVEL_COLOR[fromLevel]} />
        <text x={24} y={centerY - 6} fill="var(--muted)" fontSize="10.5">
          From {from.name ? `· ${from.name.slice(0, 22)}` : ''}
        </text>
        <text
          x={24}
          y={centerY + 12}
          fill="var(--text)"
          fontSize="12.5"
          fontWeight="600"
          fontFamily="var(--font-mono)"
        >
          {from.domain.length > 24 ? `${from.domain.slice(0, 23)}…` : from.domain}
        </text>
      </svg>
      <figcaption className="mt-2 text-[12px] text-muted">
        Colour shows the worst indicator for each node. Select a node to open its evidence.
      </figcaption>
    </figure>
  );
}
