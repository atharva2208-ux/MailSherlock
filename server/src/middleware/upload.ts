import multer from 'multer';
import { badRequest } from '../utils/errors.js';

const ALLOWED_EXTENSIONS = /\.(?:eml|txt|mbox)$/i;
const ALLOWED_TYPES = new Set([
  'message/rfc822',
  'text/plain',
  'application/octet-stream',
  'application/mbox',
  '',
]);

/**
 * Uploads are held in memory only - never written to disk - and bounded in
 * size and count. The real content check happens in the parser, which
 * rejects anything without an RFC 5322 header block.
 */
export function createUpload(maxBytes: number) {
  return multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: maxBytes, files: 1, fields: 4, fieldSize: 1024, parts: 6 },
    fileFilter: (_req, file, callback) => {
      if (file.originalname.toLowerCase().endsWith('.msg')) {
        callback(
          badRequest(
            'unsupported_format',
            'Outlook .msg files are not supported. Save the message as .eml (File > Save As) and upload that.',
          ),
        );
        return;
      }
      if (!ALLOWED_EXTENSIONS.test(file.originalname) || !ALLOWED_TYPES.has(file.mimetype)) {
        callback(
          badRequest(
            'unsupported_file',
            'Only .eml (RFC 5322) or plain-text email files are accepted.',
          ),
        );
        return;
      }
      callback(null, true);
    },
  });
}
