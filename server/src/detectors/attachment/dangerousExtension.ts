import type { Detector } from '../types.js';
import { attachmentFinding } from './attachmentFinding.js';

export const dangerousExtensionDetector: Detector = {
  id: 'attachment.dangerous_type',
  category: 'attachment',
  description: 'Executable, script, disk-image, macro and HTML attachments',
  run: ({ attachments }) =>
    attachmentFinding(
      attachments,
      ['executable', 'disk_image', 'macro', 'html_attachment', 'archive_executable'],
      {
        confidence: 0.95,
        title: 'Dangerous attachment type',
        describe: (names) =>
          `Attachment(s) ${names.join(', ')} can execute code or render a phishing page when opened.`,
        whyItMatters:
          'These file types are the primary malware delivery vehicles in email. Business documents are almost never sent as executables, scripts or disk images.',
        recommendation:
          'Do not open. Submit the hash to a sandbox or threat-intelligence service and quarantine the message.',
        method:
          'Classified attachments by final extension, inspected ZIP central directories without extracting, and checked file signatures.',
      },
    ),
};
