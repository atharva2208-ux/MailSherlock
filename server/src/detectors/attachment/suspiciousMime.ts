import type { Detector } from '../types.js';
import { attachmentFinding } from './attachmentFinding.js';

export const suspiciousMimeDetector: Detector = {
  id: 'attachment.type_mismatch',
  category: 'attachment',
  description: 'Content signature contradicts the declared name or MIME type',
  run: ({ attachments }) =>
    attachmentFinding(attachments, ['type_mismatch'], {
      confidence: 0.95,
      title: 'Attachment content does not match its name',
      describe: (names) =>
        `The bytes of ${names.join(', ')} identify a different file type than the filename claims.`,
      whyItMatters:
        'A mismatch between the file signature and the extension means the sender intentionally mislabelled the file.',
      recommendation: 'Quarantine and analyse in a sandbox.',
      method:
        'Compared magic-byte file signatures with the filename extension and declared Content-Type.',
    }),
};
