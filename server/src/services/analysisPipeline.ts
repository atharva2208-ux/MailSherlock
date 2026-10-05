import type { AppConfig } from '../config/env.js';
import { ENGINE_VERSION } from '../config/env.js';
import { runDetectors } from '../detectors/registry.js';
import type { DetectionContext } from '../detectors/types.js';
import type {
  AnalysisEvent,
  AnalysisResult,
  AnalysisStageId,
  Finding,
  MlAssessment,
  StageTiming,
  ThreatIntelResult,
} from '../models/analysis.js';
import type { AnalysisRepository } from '../repositories/analysisRepository.js';
import { newId } from '../utils/ids.js';
import type { Logger } from '../utils/logger.js';
import { analyseAttachment } from './analyzers/attachments.js';
import { summariseAuthentication } from './analyzers/authentication.js';
import { analyseContent } from './analyzers/contentSignals.js';
import { assessLookalike, FREE_MAIL_DOMAINS } from './analyzers/domain.js';
import { analyseReceivedChain } from './analyzers/receivedChain.js';
import { extractUrls } from './analyzers/urls.js';
import type { MlClient } from './enrichment/mlClient.js';
import type { ThreatIntelService } from './enrichment/threatIntel.js';
import { headerValues, orgDomain } from './parser/headers.js';
import { parseEmail, type ParsedMessage } from './parser/parseEmail.js';
import { applyTrustAdjustments, assessTrust } from './scoring/correlation.js';
import { scoreRisk } from './scoring/riskScore.js';

export const STAGE_LABELS: Record<AnalysisStageId, string> = {
  parse: 'Email parsed',
  headers: 'Headers extracted',
  authentication: 'Authentication analysed',
  urls: 'URLs extracted',
  content: 'Content analysed',
  attachments: 'Attachments inspected',
  rules: 'Detection engine',
  ml: 'ML classifier',
  threat_intel: 'Threat intelligence',
  correlation: 'Evidence correlated',
  scoring: 'Risk calculated',
  persist: 'Investigation saved',
};

export interface PipelineDeps {
  config: AppConfig;
  logger: Logger;
  repository: AnalysisRepository;
  ml: MlClient;
  threatIntel: ThreatIntelService;
}

export interface AnalyzeInput {
  raw: Buffer;
  sourceName: string;
  onEvent?: (event: AnalysisEvent) => void;
}

class StageRecorder {
  readonly stages: StageTiming[] = [];
  constructor(private readonly emit?: (event: AnalysisEvent) => void) {}

  async run<T>(
    id: AnalysisStageId,
    fn: () => T | Promise<T>,
    describe?: (value: T) => Pick<StageTiming, 'status' | 'detail'> | undefined,
  ): Promise<T> {
    const started = performance.now();
    const value = await fn();
    const extra = describe?.(value);
    const stage: StageTiming = {
      id,
      label: STAGE_LABELS[id],
      status: extra?.status ?? 'done',
      durationMs: Math.round((performance.now() - started) * 100) / 100,
      detail: extra?.detail,
    };
    this.stages.push(stage);
    this.emit?.({ type: 'stage', stage });
    return value;
  }
}

function buildContext(
  message: ParsedMessage,
): Omit<DetectionContext, 'authentication' | 'urls' | 'content' | 'attachments'> {
  const from = message.metadata.from;
  const domain = from?.domain || undefined;
  const org = domain ? orgDomain(domain) : undefined;
  return {
    message,
    metadata: message.metadata,
    text: message.body.text,
    received: analyseReceivedChain(headerValues(message.headers, 'received')),
    sender: {
      address: from?.address,
      domain,
      orgDomain: org,
      displayName: from?.name ?? '',
      lookalike: domain ? assessLookalike(domain) : null,
      isFreeMail: org ? FREE_MAIL_DOMAINS.has(org) : false,
    },
  };
}

/**
 * Orchestrates one investigation. Each stage reports its real duration and
 * status; optional stages (ML, threat intelligence) degrade gracefully and
 * the analysis completes on rule-based evidence alone if they are unavailable.
 */
export async function analyzeEmail(
  deps: PipelineDeps,
  input: AnalyzeInput,
): Promise<AnalysisResult> {
  const { logger, config } = deps;
  const id = newId('an');
  const log = logger.child({ analysisId: id });
  const recorder = new StageRecorder(input.onEvent);
  log.info({ event: 'analysis.started', bytes: input.raw.length }, 'analysis started');

  const message = await recorder.run(
    'parse',
    () => parseEmail(input.raw),
    (m) => ({
      status: 'done',
      detail: `${m.mimeStructure.length} MIME part(s), ${m.headers.length} headers`,
    }),
  );
  log.info(
    {
      event: 'email.parsed',
      headers: message.headers.length,
      parts: message.mimeStructure.length,
      attachments: message.attachments.length,
    },
    'email parsed',
  );

  const base = await recorder.run(
    'headers',
    () => buildContext(message),
    (c) => ({ status: 'done', detail: `${c.received.length} relay hop(s)` }),
  );
  const authentication = await recorder.run(
    'authentication',
    () =>
      summariseAuthentication({
        authResults: headerValues(message.headers, 'authentication-results'),
        receivedSpf: headerValues(message.headers, 'received-spf'),
        dkimSignatures: headerValues(message.headers, 'dkim-signature'),
        fromDomain: base.sender.domain,
      }),
    (a) => ({
      status: 'done',
      detail: `SPF ${a.spf.state}, DKIM ${a.dkim.state}, DMARC ${a.dmarc.state}`,
    }),
  );
  const urls = await recorder.run(
    'urls',
    () => extractUrls(message.body.text, message.htmlInspection),
    (u) => ({ status: 'done', detail: `${u.length} URL(s)` }),
  );
  const content = await recorder.run(
    'content',
    () =>
      analyseContent(message.body.text, message.metadata.subject, {
        callToAction:
          urls.some((u) => u.source !== 'image') || Boolean(message.htmlInspection?.forms.length),
      }),
    (c) => ({ status: 'done', detail: `${Object.keys(c.intents).length} intent signal(s)` }),
  );
  const attachments = await recorder.run(
    'attachments',
    () => message.attachments.map(analyseAttachment),
    (a) => ({ status: 'done', detail: `${a.length} attachment(s)` }),
  );

  const ctx: DetectionContext = { ...base, authentication, urls, content, attachments };
  const detection = await recorder.run(
    'rules',
    () => runDetectors(ctx),
    (d) => ({
      status: d.failures.length ? 'failed' : 'done',
      detail: `${d.findings.length} finding(s)${d.failures.length ? `, ${d.failures.length} detector error(s)` : ''}`,
    }),
  );
  for (const failure of detection.failures)
    log.error({ event: 'detector.failed', ...failure }, 'detector failed');
  log.info(
    { event: 'detectors.executed', findings: detection.findings.length },
    'detectors executed',
  );

  log.debug({ event: 'ml.started' }, 'ML inference started');
  const ml: MlAssessment = await recorder.run(
    'ml',
    () => deps.ml.predict(input.raw),
    (m) =>
      m.available
        ? {
            status: 'done',
            detail: `P(phishing) ${((m.probability ?? 0) * 100).toFixed(1)}% · model v${m.modelVersion}`,
          }
        : { status: 'skipped', detail: m.reason },
  );

  let threatIntel: ThreatIntelResult[] = [];
  let tiFindings: Omit<Finding, 'id'>[] = [];
  await recorder.run(
    'threat_intel',
    async () => {
      if (!config.ENRICH_ON_ANALYZE || !deps.threatIntel.anyConfigured) return null;
      const enrichment = await deps.threatIntel.enrich({
        domains: [
          base.sender.orgDomain ?? '',
          ...urls.filter((u) => u.source !== 'image').map((u) => u.registrableDomain),
        ],
        ips: base.received.map((h) => h.fromIp ?? '').slice(0, 1),
      });
      threatIntel = enrichment.results;
      tiFindings = enrichment.findings;
      return enrichment;
    },
    (e) =>
      e === null
        ? {
            status: 'skipped',
            detail: deps.threatIntel.anyConfigured
              ? 'Automatic enrichment disabled (ENRICH_ON_ANALYZE=false)'
              : 'No external providers configured',
          }
        : { status: 'done', detail: `${e.results.length} provider result(s)` },
  );

  const allFindings: Finding[] = [
    ...detection.findings,
    ...tiFindings.map((f, i) => ({ ...f, id: `t${i + 1}` })),
  ];
  const { findings, trust } = await recorder.run(
    'correlation',
    () => {
      const trustContext = assessTrust(ctx, allFindings);
      return { findings: applyTrustAdjustments(allFindings, trustContext), trust: trustContext };
    },
    (r) => ({
      status: 'done',
      detail: r.trust.trusted
        ? 'Trusted sender context applied'
        : `${r.trust.blockers.length} trust blocker(s)`,
    }),
  );

  const risk = await recorder.run(
    'scoring',
    () => scoreRisk(findings, ml, trust),
    (r) => ({ status: 'done', detail: `${r.score}/100 · ${r.level}` }),
  );

  const result: AnalysisResult = {
    id,
    createdAt: new Date().toISOString(),
    sourceName: input.sourceName,
    sizeBytes: message.sizeBytes,
    sha256: message.sha256,
    metadata: message.metadata,
    body: message.body,
    received: base.received,
    authentication,
    urls,
    attachments,
    mimeStructure: message.mimeStructure,
    findings,
    ml,
    threatIntel,
    risk,
    stages: recorder.stages,
    parseWarnings: message.warnings,
    engineVersion: ENGINE_VERSION,
  };

  await recorder.run('persist', () =>
    deps.repository.insert(result, config.STORE_RAW_SOURCE ? message.raw : null),
  );
  result.stages = recorder.stages;
  log.info(
    {
      event: 'analysis.completed',
      score: risk.score,
      level: risk.level,
      classification: risk.classification,
      findings: findings.length,
      ml: ml.available,
    },
    'analysis completed',
  );
  return result;
}
