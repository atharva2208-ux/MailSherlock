import type {
  AttachmentInfo,
  AuthenticationSummary,
  EmailMetadata,
  ExtractedUrl,
  Finding,
  FindingCategory,
  ReceivedHop,
} from '../models/analysis.js';
import type { ContentAnalysis } from '../services/analyzers/contentSignals.js';
import type { LookalikeMatch } from '../services/analyzers/domain.js';
import type { ParsedMessage } from '../services/parser/parseEmail.js';

export interface DetectionContext {
  message: ParsedMessage;
  metadata: EmailMetadata;
  text: string;
  authentication: AuthenticationSummary;
  received: ReceivedHop[];
  urls: ExtractedUrl[];
  attachments: AttachmentInfo[];
  content: ContentAnalysis;
  sender: {
    address?: string;
    domain?: string;
    orgDomain?: string;
    displayName: string;
    lookalike: LookalikeMatch | null;
    isFreeMail: boolean;
  };
}

/** What a detector reports; the engine fills in identity and provenance. */
export type DetectorFinding = Omit<Finding, 'id' | 'detector' | 'category' | 'source'>;

export interface Detector {
  id: string;
  category: FindingCategory;
  description: string;
  run(ctx: DetectionContext): DetectorFinding[];
}

export const ATTACK = {
  phishing: 'T1566',
  spearphishingAttachment: 'T1566.001',
  spearphishingLink: 'T1566.002',
  impersonation: 'T1656',
  mfaFatigue: 'T1621',
  masquerading: 'T1036',
  doubleExtension: 'T1036.007',
  rtlo: 'T1036.002',
} as const;
