import type { AnalysisResult, Severity } from '../../models/analysis.js';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Structured investigation report for export (JSON) and for the printable
 * report view. Sections mirror what an incident ticket needs.
 */
export function buildReport(analysis: AnalysisResult) {
  const findings = [...analysis.findings].sort(
    (a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity),
  );
  const recommendations = [
    ...new Set(findings.filter((f) => f.severity !== 'info').map((f) => f.recommendation)),
  ];
  return {
    report: {
      title: 'MailSherlock - Email Security Investigation Report',
      generatedAt: new Date().toISOString(),
      analysisId: analysis.id,
      engineVersion: analysis.engineVersion,
    },
    executiveSummary: analysis.risk.summary,
    verdict: {
      riskScore: analysis.risk.score,
      riskLevel: analysis.risk.level,
      classification: analysis.risk.classification,
      ruleScore: analysis.risk.ruleScore,
      scoreBreakdown: analysis.risk.contributions,
      trustedSenderContext: analysis.risk.trustedContext,
    },
    emailMetadata: {
      from: analysis.metadata.from,
      replyTo: analysis.metadata.replyTo,
      returnPath: analysis.metadata.returnPath,
      to: analysis.metadata.to,
      subject: analysis.metadata.subject,
      date: analysis.metadata.date,
      messageId: analysis.metadata.messageId,
      sha256: analysis.sha256,
      sizeBytes: analysis.sizeBytes,
    },
    authentication: analysis.authentication,
    headerAnalysis: { receivedChain: analysis.received, warnings: analysis.parseWarnings },
    indicators: findings,
    urlAnalysis: analysis.urls,
    attachmentAnalysis: analysis.attachments,
    machineLearning: analysis.ml,
    threatIntelligence: analysis.threatIntel,
    iocs: {
      domains: [
        ...new Set(
          [
            analysis.metadata.from?.domain,
            ...analysis.urls.filter((u) => u.risk !== 'none').map((u) => u.host),
          ].filter(Boolean),
        ),
      ],
      urls: analysis.urls.filter((u) => u.risk !== 'none').map((u) => u.url),
      ips: [...new Set(analysis.received.map((h) => h.fromIp).filter(Boolean))],
      attachmentHashes: analysis.attachments.map((a) => ({
        filename: a.filename,
        sha256: a.sha256,
        md5: a.md5,
      })),
    },
    recommendations,
    analystFeedback: analysis.feedback ?? null,
  };
}
