/**
 * Domain model for an investigation. These types are the API contract and are
 * imported (type-only) by the client, so they stay free of runtime code.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';
export type Classification = 'phishing' | 'suspicious' | 'legitimate';
export type FindingSource = 'rule' | 'threat_intel';

export type FindingCategory =
  | 'authentication'
  | 'header'
  | 'sender'
  | 'impersonation'
  | 'domain'
  | 'url'
  | 'content'
  | 'attachment'
  | 'threat_intel';

export interface EvidenceItem {
  label: string;
  value: string;
}

/** A span of `bodyText` that supports a finding. Offsets are UTF-16 indices. */
export interface TextSpan {
  start: number;
  end: number;
  text: string;
}

export interface SeverityAdjustment {
  from: Severity;
  to: Severity;
  reason: string;
}

export interface Finding {
  id: string;
  detector: string;
  category: FindingCategory;
  severity: Severity;
  /** 0..1 - how sure the detector is that the indicator is present and meaningful. */
  confidence: number;
  title: string;
  description: string;
  whyItMatters: string;
  evidence: EvidenceItem[];
  recommendation: string;
  source: FindingSource;
  /** Detection method in plain words, shown to analysts. */
  method: string;
  /** MITRE ATT&CK technique identifiers where one clearly applies. */
  attack?: string[];
  spans?: TextSpan[];
  relatedUrls?: string[];
  /** Scoring group used to avoid double counting correlated evidence. */
  scoreGroup: string;
  adjustment?: SeverityAdjustment;
}

export interface Mailbox {
  name: string;
  address: string;
  domain: string;
}

export interface ReceivedHop {
  index: number;
  raw: string;
  from?: string;
  fromIp?: string;
  by?: string;
  with?: string;
  timestamp?: string;
  /** Seconds since the previous hop (chronological order). */
  delaySeconds?: number;
  flags: string[];
}

export type AuthState = 'pass' | 'fail' | 'not_present' | 'unknown';

export interface AuthCheck {
  state: AuthState;
  /** Verbatim result keyword from the header (e.g. softfail, temperror). */
  result?: string;
  domain?: string;
  aligned?: boolean;
  detail: string;
}

export interface AuthenticationSummary {
  spf: AuthCheck;
  dkim: AuthCheck;
  dmarc: AuthCheck;
  source?: string;
  headerCount: number;
  dkimSignaturePresent: boolean;
}

export type UrlSource = 'text' | 'anchor' | 'form' | 'image';

export interface UrlIndicator {
  id: string;
  label: string;
  severity: Severity;
}

export interface ExtractedUrl {
  id: string;
  url: string;
  source: UrlSource;
  host: string;
  registrableDomain: string;
  unicodeHost?: string;
  anchorText?: string;
  indicators: UrlIndicator[];
  risk: Severity | 'none';
}

export interface AttachmentInfo {
  id: string;
  filename: string;
  extension: string;
  declaredType: string;
  detectedType?: string;
  size: number;
  sha256: string;
  md5: string;
  archiveEntries?: string[];
  indicators: UrlIndicator[];
  risk: Severity | 'none';
}

export interface MlSignal {
  kind: 'term' | 'structural' | 'character_patterns';
  feature: string;
  weight: number;
}

export interface MlAssessment {
  available: boolean;
  reason?: string;
  modelName?: string;
  modelVersion?: string;
  probability?: number;
  threshold?: number;
  label?: Classification;
  confidence?: 'high' | 'medium' | 'low';
  vocabularyCoverage?: number;
  signals?: MlSignal[];
  inferenceMs?: number;
}

export interface ThreatIntelResult {
  provider: string;
  target: string;
  status: 'ok' | 'not_configured' | 'error' | 'skipped';
  verdict?: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  summary?: string;
  details?: Record<string, string | number | boolean | null>;
  link?: string;
}

export interface ScoreContribution {
  label: string;
  points: number;
  kind: 'rule' | 'ml' | 'correlation' | 'trust';
  detail?: string;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  classification: Classification;
  ruleScore: number;
  /** Sum of all contributions before normalisation onto 0-100. */
  rawPoints: number;
  contributions: ScoreContribution[];
  trustedContext: boolean;
  summary: string;
}

export interface StageTiming {
  id: AnalysisStageId;
  label: string;
  status: 'done' | 'skipped' | 'failed';
  durationMs: number;
  detail?: string;
}

export type AnalysisStageId =
  | 'parse'
  | 'headers'
  | 'authentication'
  | 'urls'
  | 'content'
  | 'attachments'
  | 'rules'
  | 'ml'
  | 'threat_intel'
  | 'correlation'
  | 'scoring'
  | 'persist';

export interface EmailMetadata {
  from?: Mailbox;
  replyTo?: Mailbox[];
  returnPath?: string;
  to: Mailbox[];
  cc: Mailbox[];
  bcc: Mailbox[];
  subject: string;
  date?: string;
  messageId?: string;
  userAgent?: string;
  xMailer?: string;
  headers: { name: string; value: string }[];
}

export interface EmailBody {
  /** Canonical visible text; finding spans index into this string. */
  text: string;
  textSource: 'plain' | 'html' | 'none';
  /** Sanitised HTML safe to render in a sandboxed frame, if the message had HTML. */
  sanitizedHtml?: string;
  hasHtml: boolean;
  truncated: boolean;
}

export interface MimePart {
  path: string;
  contentType: string;
  filename?: string;
  size?: number;
}

export interface AnalysisResult {
  id: string;
  createdAt: string;
  sourceName: string;
  sizeBytes: number;
  sha256: string;
  metadata: EmailMetadata;
  body: EmailBody;
  received: ReceivedHop[];
  authentication: AuthenticationSummary;
  urls: ExtractedUrl[];
  attachments: AttachmentInfo[];
  mimeStructure: MimePart[];
  findings: Finding[];
  ml: MlAssessment;
  threatIntel: ThreatIntelResult[];
  risk: RiskAssessment;
  stages: StageTiming[];
  parseWarnings: string[];
  engineVersion: string;
  feedback?: AnalystFeedback;
}

export type FeedbackVerdict =
  'confirmed_phishing' | 'confirmed_legitimate' | 'false_positive' | 'false_negative' | 'uncertain';

export interface AnalystFeedback {
  verdict: FeedbackVerdict;
  notes?: string;
  createdAt: string;
}

export interface AnalysisSummary {
  id: string;
  createdAt: string;
  sourceName: string;
  sender: string;
  senderDomain: string;
  subject: string;
  riskScore: number;
  riskLevel: RiskLevel;
  classification: Classification;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  mlProbability: number | null;
  modelVersion: string | null;
  feedback: FeedbackVerdict | null;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface DashboardStats {
  totals: {
    investigations: number;
    threats: number;
    suspicious: number;
    criticalFindings: number;
    highRisk: number;
    falsePositives: number;
    feedbackCount: number;
  };
  classification: Record<Classification, number>;
  riskDistribution: Record<RiskLevel, number>;
  categories: { category: FindingCategory; count: number }[];
  history: {
    date: string;
    total: number;
    phishing: number;
    suspicious: number;
    legitimate: number;
  }[];
  topIndicators: { title: string; count: number; severity: Severity }[];
}

export interface ComponentHealth {
  status: 'up' | 'down' | 'degraded' | 'not_configured';
  detail: string;
  latencyMs?: number;
}

export interface HealthReport {
  status: 'ok' | 'degraded';
  version: string;
  uptimeSeconds: number;
  components: {
    api: ComponentHealth;
    database: ComponentHealth;
    ml: ComponentHealth;
    storage: ComponentHealth;
    threatIntel: Record<string, ComponentHealth>;
  };
}

export type AnalysisEvent =
  | { type: 'stage'; stage: StageTiming }
  | { type: 'result'; analysis: AnalysisResult }
  | { type: 'error'; error: ApiErrorBody };

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}
