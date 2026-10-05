import { describe, expect, it } from 'vitest';
import {
  analyseAttachment,
  listZipEntries,
  sanitiseFilename,
} from '../../src/services/analyzers/attachments.js';
import { buildZip } from '../helpers.js';

const attach = (filename: string, content: Buffer, contentType = 'application/octet-stream') =>
  analyseAttachment({ filename, content, contentType, size: content.length }, 0);

describe('attachment analysis', () => {
  it('hashes content with SHA-256 and MD5', () => {
    const info = attach('notes.txt', Buffer.from('abc'));
    expect(info.sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(info.md5).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(info.risk).toBe('none');
  });

  it('flags executables, double extensions and signature mismatches', () => {
    const pe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64)]);
    const ids = attach('invoice.pdf.exe', pe).indicators.map((i) => i.id);
    expect(ids).toEqual(expect.arrayContaining(['executable', 'double_extension']));
    expect(attach('report.pdf', pe).indicators.map((i) => i.id)).toContain('type_mismatch');
    expect(attach('macro.docm', Buffer.from('PK')).indicators.map((i) => i.id)).toContain('macro');
  });

  it('flags right-to-left override filenames', () => {
    expect(attach('invoice‮fdp.exe', Buffer.from('x')).indicators.map((i) => i.id)).toContain(
      'rtlo',
    );
  });

  it('lists ZIP entries without extracting and flags executables inside', () => {
    const zip = buildZip(['docs/readme.txt', 'payload.js']);
    expect(listZipEntries(zip)).toEqual(['docs/readme.txt', 'payload.js']);
    const info = attach('archive.zip', zip, 'application/zip');
    expect(info.archiveEntries).toEqual(['docs/readme.txt', 'payload.js']);
    expect(info.indicators.map((i) => i.id)).toContain('archive_executable');
  });

  it('sanitises path traversal and control characters in filenames', () => {
    expect(sanitiseFilename('../../etc/passwd')).toBe('passwd');
    expect(sanitiseFilename('..\\..\\windows\\evil.exe')).toBe('evil.exe');
    expect(sanitiseFilename('\u0000\u0007')).toBe('unnamed');
  });
});
