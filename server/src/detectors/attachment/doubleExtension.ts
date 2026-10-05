import type { Detector } from '../types.js';
import { ATTACK } from '../types.js';
import { attachmentFinding } from './attachmentFinding.js';

export const doubleExtensionDetector: Detector = {
  id: 'attachment.disguised_name',
  category: 'attachment',
  description: 'Double extensions and right-to-left override filenames',
  run: ({ attachments }) =>
    attachmentFinding(attachments, ['double_extension', 'rtlo'], {
      confidence: 0.97,
      title: 'Attachment name disguises its real type',
      describe: (names) =>
        `${names.join(', ')} uses a decoy extension so it looks like a document.`,
      whyItMatters:
        'Windows hides known extensions by default, so "invoice.pdf.exe" is displayed as "invoice.pdf". This is deliberate masquerading.',
      recommendation: 'Do not open. Treat the message as malicious.',
      method:
        'Split filenames into extension chains and checked for decoy-then-executable patterns and Unicode bidi override characters.',
      attack: [ATTACK.doubleExtension, ATTACK.rtlo],
    }),
};
