import { getDomain } from 'tldts';
import type { Mailbox } from '../../models/analysis.js';

export interface RawHeader {
  name: string;
  value: string;
}

const HEADER_LINE = /^([!-9;-~]+):[ \t]*(.*)$/;

/** Split the header block off a raw message. Returns null if there is none. */
export function splitHeaderBlock(raw: string): { headerBlock: string; body: string } | null {
  const match = /\r?\n\r?\n/.exec(raw);
  const headerBlock = match ? raw.slice(0, match.index) : raw;
  const body = match ? raw.slice(match.index + match[0].length) : '';
  const firstLine = headerBlock.split(/\r?\n/, 1)[0] ?? '';
  // mbox "From " separator lines precede the real headers in some exports.
  const candidate = firstLine.startsWith('From ')
    ? (headerBlock.split(/\r?\n/).slice(1)[0] ?? '')
    : firstLine;
  return HEADER_LINE.test(candidate) ? { headerBlock, body } : null;
}

/** Parse and unfold headers, preserving order and duplicates (forensically significant). */
export function parseRawHeaders(headerBlock: string, limit = 500): RawHeader[] {
  const headers: RawHeader[] = [];
  for (const line of headerBlock.split(/\r?\n/)) {
    if (line.startsWith('From ') && headers.length === 0) continue;
    if (/^[ \t]/.test(line) && headers.length) {
      const last = headers[headers.length - 1]!;
      last.value = `${last.value} ${line.trim()}`;
      continue;
    }
    const match = HEADER_LINE.exec(line);
    if (match) {
      if (headers.length >= limit) break;
      headers.push({ name: match[1]!, value: match[2]!.trim() });
    }
  }
  return headers;
}

export function headerValues(headers: RawHeader[], name: string): string[] {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
}

export function firstHeader(headers: RawHeader[], name: string): string | undefined {
  return headerValues(headers, name)[0];
}

export function domainOfAddress(address: string): string {
  const at = address.lastIndexOf('@');
  return at >= 0
    ? address
        .slice(at + 1)
        .toLowerCase()
        .replace(/[>\s]+$/, '')
    : '';
}

/** Organisational domain (registrable domain per the Public Suffix List). */
export function orgDomain(host: string): string {
  const clean = host.toLowerCase().replace(/\.$/, '');
  return getDomain(clean, { allowPrivateDomains: false }) ?? clean;
}

export function toMailbox(
  name: string | undefined,
  address: string | undefined,
): Mailbox | undefined {
  if (!address) return undefined;
  const normalised = address.trim().toLowerCase();
  return { name: (name ?? '').trim(), address: normalised, domain: domainOfAddress(normalised) };
}

/** Extract the address from a Return-Path value such as "<bounce@x.com>". */
export function returnPathAddress(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const match = /<([^>]*)>/.exec(value);
  const address = (match ? match[1] : value)?.trim();
  return address ? address.toLowerCase() : undefined;
}
