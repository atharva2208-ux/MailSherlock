import { createHash } from 'node:crypto';
import type { AttachmentInfo, UrlIndicator } from '../../models/analysis.js';
import type { ParsedAttachment } from '../parser/parseEmail.js';
import { maxSeverity } from './urls.js';

export const EXECUTABLE_EXTENSIONS = new Set(
  'exe scr com pif cpl msi msp dll js jse vbs vbe wsf wsh ps1 psm1 bat cmd hta lnk reg jar sct inf application gadget'.split(
    ' ',
  ),
);
const CONTAINER_EXTENSIONS = new Set('iso img vhd vhdx'.split(' '));
const ARCHIVE_EXTENSIONS = new Set('zip rar 7z gz tgz tar cab ace arj'.split(' '));
const MACRO_EXTENSIONS = new Set('docm dotm xlsm xltm xlam pptm potm ppam sldm'.split(' '));
const MARKUP_EXTENSIONS = new Set('html htm shtml svg xhtml'.split(' '));
const DECOY_EXTENSIONS = new Set(
  'pdf doc docx xls xlsx ppt pptx txt jpg jpeg png gif rtf csv'.split(' '),
);

/** File signatures ("magic bytes") for formats relevant to triage. */
function sniffType(content: Buffer): string | undefined {
  const head = content.subarray(0, 8);
  if (head[0] === 0x4d && head[1] === 0x5a) return 'application/x-msdownload (PE executable)';
  if (head[0] === 0x7f && head.toString('latin1', 1, 4) === 'ELF') return 'application/x-elf';
  if (head.toString('latin1', 0, 4) === '%PDF') return 'application/pdf';
  if (head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04)
    return 'application/zip (or OOXML)';
  if (head.toString('latin1', 0, 4) === 'Rar!') return 'application/x-rar';
  if (head[0] === 0x37 && head[1] === 0x7a && head[2] === 0xbc && head[3] === 0xaf)
    return 'application/x-7z-compressed';
  if (head[0] === 0xd0 && head[1] === 0xcf && head[2] === 0x11 && head[3] === 0xe0)
    return 'application/x-ole-storage (legacy Office)';
  if (head[0] === 0x89 && head.toString('latin1', 1, 4) === 'PNG') return 'image/png';
  if (head[0] === 0xff && head[1] === 0xd8) return 'image/jpeg';
  if (head.toString('latin1', 0, 4) === 'GIF8') return 'image/gif';
  if (content.length > 0x8006 && content.toString('latin1', 0x8001, 0x8006) === 'CD001')
    return 'application/x-iso9660-image';
  if (head[0] === 0x4c && head[1] === 0x00 && head[2] === 0x00 && head[3] === 0x00)
    return 'application/x-ms-shortcut (LNK)';
  const textStart = content.subarray(0, 512).toString('latin1').trimStart().toLowerCase();
  if (
    textStart.startsWith('<!doctype html') ||
    textStart.startsWith('<html') ||
    textStart.startsWith('<script')
  )
    return 'text/html';
  return undefined;
}

/**
 * List file names inside a ZIP by reading its central directory. Nothing is
 * decompressed or written to disk; only the directory records are parsed.
 */
export function listZipEntries(content: Buffer, limit = 200): string[] {
  const names: string[] = [];
  const searchStart = Math.max(0, content.length - 65_557);
  let eocd = -1;
  for (let i = content.length - 22; i >= searchStart; i--) {
    if (content.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return names;
  const total = content.readUInt16LE(eocd + 10);
  let offset = content.readUInt32LE(eocd + 16);
  for (let n = 0; n < Math.min(total, limit); n++) {
    if (offset + 46 > content.length || content.readUInt32LE(offset) !== 0x02014b50) break;
    const nameLength = content.readUInt16LE(offset + 28);
    const extraLength = content.readUInt16LE(offset + 30);
    const commentLength = content.readUInt16LE(offset + 32);
    names.push(content.toString('utf8', offset + 46, offset + 46 + nameLength).slice(0, 255));
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return names;
}

// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/g;

/** Strip directory components and control characters from attacker-supplied names. */
export function sanitiseFilename(name: string): string {
  const base = name.replace(CONTROL_CHARACTERS, '').split(/[\\/]/).pop() ?? '';
  const trimmed = base.replace(/^\.+/, '').trim().slice(0, 255);
  return trimmed || 'unnamed';
}

function extensionsOf(name: string): string[] {
  return name
    .toLowerCase()
    .split('.')
    .slice(1)
    .filter((part) => /^[a-z0-9]{1,8}$/.test(part));
}

export function analyseAttachment(attachment: ParsedAttachment, index: number): AttachmentInfo {
  const filename = sanitiseFilename(attachment.filename);
  // Right-to-left override (U+202E) reverses how the rest of a filename renders.
  const hasRtlo = /[‮‭‏]/.test(attachment.filename);
  const extensions = extensionsOf(filename);
  const extension = extensions.at(-1) ?? '';
  const detectedType = sniffType(attachment.content);
  const indicators: UrlIndicator[] = [];

  if (EXECUTABLE_EXTENSIONS.has(extension))
    indicators.push({
      id: 'executable',
      label: `Executable/script file type ".${extension}"`,
      severity: 'critical',
    });
  if (CONTAINER_EXTENSIONS.has(extension))
    indicators.push({
      id: 'disk_image',
      label: `Disk image ".${extension}" (bypasses Mark-of-the-Web)`,
      severity: 'high',
    });
  if (MACRO_EXTENSIONS.has(extension))
    indicators.push({
      id: 'macro',
      label: `Macro-enabled Office document ".${extension}"`,
      severity: 'high',
    });
  if (MARKUP_EXTENSIONS.has(extension))
    indicators.push({
      id: 'html_attachment',
      label: 'HTML/SVG attachment (often a local credential-phishing page)',
      severity: 'high',
    });
  if (
    extensions.length >= 2 &&
    DECOY_EXTENSIONS.has(extensions.at(-2)!) &&
    !DECOY_EXTENSIONS.has(extension)
  ) {
    indicators.push({
      id: 'double_extension',
      label: `Double extension ".${extensions.at(-2)}.${extension}" disguises the real type`,
      severity: 'critical',
    });
  }
  if (hasRtlo)
    indicators.push({
      id: 'rtlo',
      label: 'Right-to-left override character hides the real extension',
      severity: 'critical',
    });
  if (detectedType?.includes('PE executable') && !EXECUTABLE_EXTENSIONS.has(extension)) {
    indicators.push({
      id: 'type_mismatch',
      label: `Content is a Windows executable despite the ".${extension}" name`,
      severity: 'critical',
    });
  } else if (detectedType && extension === 'pdf' && detectedType !== 'application/pdf') {
    indicators.push({
      id: 'type_mismatch',
      label: `Named .pdf but content is ${detectedType}`,
      severity: 'high',
    });
  }

  let archiveEntries: string[] | undefined;
  if (ARCHIVE_EXTENSIONS.has(extension) || detectedType?.startsWith('application/zip')) {
    if (detectedType?.startsWith('application/zip'))
      archiveEntries = listZipEntries(attachment.content);
    if (ARCHIVE_EXTENSIONS.has(extension))
      indicators.push({
        id: 'archive',
        label: 'Archive attachment (contents not scanned by many gateways)',
        severity: 'low',
      });
    const risky = (archiveEntries ?? []).filter((entry) => {
      const ext = extensionsOf(entry).at(-1) ?? '';
      return (
        EXECUTABLE_EXTENSIONS.has(ext) ||
        CONTAINER_EXTENSIONS.has(ext) ||
        MARKUP_EXTENSIONS.has(ext)
      );
    });
    if (risky.length)
      indicators.push({
        id: 'archive_executable',
        label: `Archive contains ${risky.slice(0, 3).join(', ')}`,
        severity: 'critical',
      });
  }
  if (attachment.size === 0)
    indicators.push({
      id: 'empty',
      label: 'Attachment is empty or failed to decode',
      severity: 'info',
    });

  return {
    id: `a${index + 1}`,
    filename,
    extension,
    declaredType: attachment.contentType,
    detectedType,
    size: attachment.size,
    sha256: createHash('sha256').update(attachment.content).digest('hex'),
    md5: createHash('md5').update(attachment.content).digest('hex'),
    archiveEntries,
    indicators,
    risk: maxSeverity(indicators.map((i) => i.severity)),
  };
}
