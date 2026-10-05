import type { MimePart } from '../../models/analysis.js';
import { firstHeader, parseRawHeaders, splitHeaderBlock } from './headers.js';

const MAX_DEPTH = 12;
const MAX_PARTS = 300;

function param(value: string, name: string): string | undefined {
  const match = new RegExp(`${name}\\*?=\\s*(?:"([^"]*)"|([^;\\s]+))`, 'i').exec(value);
  return match ? (match[1] ?? match[2]) : undefined;
}

/**
 * Describe the MIME tree for the forensic view. This walks boundaries only;
 * decoding is left to the full parser. Depth and part limits stop
 * maliciously nested messages from exhausting resources.
 */
export function describeMimeStructure(raw: string): { parts: MimePart[]; warnings: string[] } {
  const parts: MimePart[] = [];
  const warnings: string[] = [];

  const walk = (entity: string, path: string, depth: number) => {
    if (parts.length >= MAX_PARTS) return;
    if (depth > MAX_DEPTH) {
      warnings.push(`MIME nesting deeper than ${MAX_DEPTH} levels was not expanded`);
      return;
    }
    const split = splitHeaderBlock(entity);
    const headers = split ? parseRawHeaders(split.headerBlock, 100) : [];
    const body = split ? split.body : entity;
    const contentType = firstHeader(headers, 'content-type') ?? 'text/plain';
    const type = contentType.split(';')[0]!.trim().toLowerCase() || 'text/plain';
    const disposition = firstHeader(headers, 'content-disposition') ?? '';
    const filename = param(disposition, 'filename') ?? param(contentType, 'name');
    parts.push({ path, contentType: type, filename, size: body.length });

    if (type.startsWith('multipart/')) {
      const boundary = param(contentType, 'boundary');
      if (!boundary) {
        warnings.push(`Part ${path} is multipart but declares no boundary`);
        return;
      }
      // RFC 2046: a delimiter is a whole line "--boundary" (optionally "--boundary--"),
      // so boundary "b1" must not match inside "--b10".
      const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const delimiter = new RegExp(`^--${escaped}(--)?[ \\t]*\\r?$`, 'gm');
      const lines = [...body.matchAll(delimiter)];
      if (!lines.some((m) => m[1] === '--'))
        warnings.push(`Part ${path} is missing its closing boundary`);
      let sectionIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        const current = lines[i]!;
        if (current[1] === '--') break;
        const start = current.index! + current[0].length;
        const end = lines[i + 1]?.index ?? body.length;
        sectionIndex += 1;
        walk(body.slice(start, end).replace(/^\r?\n/, ''), `${path}.${sectionIndex}`, depth + 1);
      }
    } else if (type === 'message/rfc822') {
      walk(body, `${path}.1`, depth + 1);
    }
  };

  walk(raw, '1', 0);
  return { parts, warnings };
}
