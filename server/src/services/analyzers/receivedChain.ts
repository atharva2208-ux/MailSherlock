import net from 'node:net';
import type { ReceivedHop } from '../../models/analysis.js';

const FROM_RE = /\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|;|$)/i;
const BY_RE = /\bby\s+([^\s;()]+)/i;
const WITH_RE = /\bwith\s+([^\s;()]+)/i;
const IP_RE = /\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})\]|\(((?:\d{1,3}\.){3}\d{1,3})\)/i;

/** Clock skew tolerated between servers before a backwards step is flagged. */
const SKEW_TOLERANCE_SECONDS = 5 * 60;
const LONG_DELAY_SECONDS = 24 * 3600;

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a = 0, b = 0] = ip.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }
  const lower = ip.toLowerCase();
  return (
    lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80')
  );
}

function parseTimestamp(value: string): string | undefined {
  const datePart = value
    .slice(value.lastIndexOf(';') + 1)
    .replace(/\([^)]*\)/g, '')
    .trim();
  if (!datePart || value.lastIndexOf(';') < 0) return undefined;
  const parsed = Date.parse(datePart);
  return Number.isNaN(parsed) ? undefined : new Date(parsed).toISOString();
}

export function parseReceivedHeader(value: string, index: number): ReceivedHop {
  const from = FROM_RE.exec(value)?.[1]?.trim();
  const ipMatch = from ? IP_RE.exec(from) : null;
  const fromIp = ipMatch ? (ipMatch[1] ?? ipMatch[2]) : undefined;
  return {
    index,
    raw: value.length > 600 ? `${value.slice(0, 600)}…` : value,
    from: from?.slice(0, 200),
    fromIp: fromIp && net.isIP(fromIp) ? fromIp : undefined,
    by: BY_RE.exec(value)?.[1],
    with: WITH_RE.exec(value)?.[1],
    timestamp: parseTimestamp(value),
    flags: [],
  };
}

/**
 * Build the chain in chronological order (origin first). Received headers are
 * prepended by each relay, so the header order is the reverse of the path.
 */
export function analyseReceivedChain(values: string[]): ReceivedHop[] {
  const hops = values.map((value, i) => parseReceivedHeader(value, i)).reverse();
  hops.forEach((hop, position) => {
    hop.index = position + 1;
    if (hop.from && /\bunknown\b/i.test(hop.from) && hop.fromIp && !isPrivateIp(hop.fromIp)) {
      hop.flags.push('no reverse DNS for sending IP');
    }
    if (!hop.timestamp) hop.flags.push('missing or unparseable timestamp');
    const previous = hops[position - 1];
    if (previous?.timestamp && hop.timestamp) {
      const delay = (Date.parse(hop.timestamp) - Date.parse(previous.timestamp)) / 1000;
      hop.delaySeconds = Math.round(delay);
      if (delay < -SKEW_TOLERANCE_SECONDS) hop.flags.push('timestamp earlier than previous hop');
      else if (delay > LONG_DELAY_SECONDS) hop.flags.push('delayed more than 24 hours');
    }
  });
  return hops;
}
