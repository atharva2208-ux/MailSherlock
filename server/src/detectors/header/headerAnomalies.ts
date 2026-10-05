import type { Detector, DetectorFinding } from '../types.js';

const BULK_SCRIPT_MAILERS =
  /phpmailer|swiftmailer|sendblaster|atomic mail|mass mail|leaf ?php|king ?mailer|turbo-?mailer/i;

export const headerAnomaliesDetector: Detector = {
  id: 'header.anomalies',
  category: 'header',
  description: 'Structural header anomalies',
  run({ metadata, message }) {
    const findings: DetectorFinding[] = [];
    const mailer = metadata.xMailer ?? metadata.userAgent;
    if (mailer && BULK_SCRIPT_MAILERS.test(mailer)) {
      findings.push({
        severity: 'low',
        confidence: 0.6,
        title: 'Sent with a scripting mail library',
        description: `The message identifies its sending software as "${mailer.slice(0, 80)}".`,
        whyItMatters:
          'Web-script mailers are routinely abused from compromised websites to send phishing. Legitimate brands rarely send customer mail this way.',
        evidence: [{ label: 'X-Mailer / User-Agent', value: mailer.slice(0, 200) }],
        recommendation: 'Consider alongside sender authentication.',
        method: 'Matched X-Mailer and User-Agent against known bulk/script mailers.',
        scoreGroup: 'header',
      });
    }
    const fromCount = message.headers.filter((h) => h.name.toLowerCase() === 'from').length;
    if (fromCount > 1) {
      findings.push({
        severity: 'high',
        confidence: 0.9,
        title: 'Multiple From headers',
        description: `The message contains ${fromCount} From headers.`,
        whyItMatters:
          'Different mail clients display different From headers. Duplicates are used to show a spoofed sender while authentication checks evaluate another.',
        evidence: message.headers
          .filter((h) => h.name.toLowerCase() === 'from')
          .map((h) => ({ label: 'From', value: h.value.slice(0, 200) })),
        recommendation: 'Treat as a deliberate spoofing attempt.',
        method: 'Counted From headers (RFC 5322 permits exactly one).',
        scoreGroup: 'sender',
      });
    }
    if (!metadata.messageId && metadata.from) {
      findings.push({
        severity: 'info',
        confidence: 0.5,
        title: 'Missing Message-ID',
        description: 'The message has no Message-ID header.',
        whyItMatters:
          'Virtually every legitimate mail system adds a Message-ID. Its absence suggests a hand-crafted or script-generated message.',
        evidence: [{ label: 'Message-ID', value: 'absent' }],
        recommendation: 'Informational.',
        method: 'Checked for the Message-ID header.',
        scoreGroup: 'header',
      });
    }
    return findings;
  },
};
