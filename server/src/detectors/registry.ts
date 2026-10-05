import type { Finding } from '../models/analysis.js';
import { dkimDetector } from './authentication/dkim.js';
import { dmarcDetector } from './authentication/dmarc.js';
import { spfDetector } from './authentication/spf.js';
import { dangerousExtensionDetector } from './attachment/dangerousExtension.js';
import { doubleExtensionDetector } from './attachment/doubleExtension.js';
import { suspiciousMimeDetector } from './attachment/suspiciousMime.js';
import { credentialRequestDetector } from './content/credentialRequest.js';
import { financialRequestDetector } from './content/financialThreat.js';
import { hiddenContentDetector } from './content/hiddenContent.js';
import { socialEngineeringDetector } from './content/socialEngineering.js';
import { scamLureDetector } from './content/suspiciousLanguage.js';
import { urgencyDetector } from './content/urgency.js';
import { headerAnomaliesDetector } from './header/headerAnomalies.js';
import { receivedChainDetector } from './header/receivedChain.js';
import { replyToMismatchDetector } from './header/replyToMismatch.js';
import { returnPathMismatchDetector } from './header/returnPathMismatch.js';
import { displayNameSpoofingDetector } from './impersonation/displayNameSpoofing.js';
import { executiveImpersonationDetector } from './impersonation/executiveImpersonation.js';
import { homoglyphDetector } from './impersonation/homoglyph.js';
import { lookalikeSenderDetector } from './impersonation/lookalikeSender.js';
import type { DetectionContext, Detector } from './types.js';
import { anchorMismatchDetector } from './url/anchorMismatch.js';
import { credentialHarvestingDetector } from './url/credentialHarvesting.js';
import { ipUrlDetector } from './url/ipUrl.js';
import { lookalikeUrlDetector } from './url/lookalikeDomain.js';
import { redirectDetector } from './url/redirect.js';
import { suspiciousTldDetector } from './url/suspiciousTld.js';
import { urlObfuscationDetector } from './url/urlObfuscation.js';

export const DETECTORS: Detector[] = [
  spfDetector,
  dkimDetector,
  dmarcDetector,
  replyToMismatchDetector,
  returnPathMismatchDetector,
  receivedChainDetector,
  headerAnomaliesDetector,
  displayNameSpoofingDetector,
  lookalikeSenderDetector,
  homoglyphDetector,
  executiveImpersonationDetector,
  ipUrlDetector,
  urlObfuscationDetector,
  redirectDetector,
  suspiciousTldDetector,
  lookalikeUrlDetector,
  anchorMismatchDetector,
  credentialHarvestingDetector,
  urgencyDetector,
  credentialRequestDetector,
  financialRequestDetector,
  socialEngineeringDetector,
  scamLureDetector,
  hiddenContentDetector,
  dangerousExtensionDetector,
  doubleExtensionDetector,
  suspiciousMimeDetector,
];

export interface DetectorRun {
  findings: Finding[];
  failures: { detector: string; error: string }[];
}

/**
 * Run every detector in isolation: a bug or hostile input that crashes one
 * detector is recorded and must not take down the whole analysis.
 */
export function runDetectors(
  ctx: DetectionContext,
  detectors: Detector[] = DETECTORS,
): DetectorRun {
  const findings: Finding[] = [];
  const failures: DetectorRun['failures'] = [];
  for (const detector of detectors) {
    try {
      for (const result of detector.run(ctx)) {
        findings.push({
          ...result,
          id: `f${findings.length + 1}`,
          detector: detector.id,
          category: detector.category,
          source: 'rule',
          confidence: Math.max(0, Math.min(1, result.confidence)),
        });
      }
    } catch (error) {
      failures.push({
        detector: detector.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return { findings, failures };
}
