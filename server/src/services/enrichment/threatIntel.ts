import net from 'node:net';
import type { AppConfig } from '../../config/env.js';
import type { Finding, ThreatIntelResult } from '../../models/analysis.js';
import type { Logger } from '../../utils/logger.js';
import { brandForOfficialDomain } from '../analyzers/brands.js';
import {
  assessHomoglyph,
  assessLookalike,
  domainInfo,
  FREE_MAIL_DOMAINS,
  SUSPICIOUS_TLDS,
} from '../analyzers/domain.js';
import { URL_SHORTENERS } from '../analyzers/urls.js';
import { abuseIpDbProvider } from './providers/abuseIpDb.js';
import { rdapProvider } from './providers/rdap.js';
import { safeBrowsingProvider } from './providers/safeBrowsing.js';
import type { TargetKind, ThreatIntelProvider } from './providers/types.js';
import { urlScanProvider } from './providers/urlScan.js';
import { virusTotalProvider } from './providers/virusTotal.js';

const CACHE_TTL_MS = 60 * 60 * 1000;
const CACHE_MAX = 1000;
const MAX_ENRICH_TARGETS = 6;

export interface LocalDomainIntel {
  domain: string;
  registrableDomain: string;
  unicodeDomain: string;
  publicSuffix: string;
  officialBrand: string | null;
  freeMailProvider: boolean;
  urlShortener: boolean;
  suspiciousTld: boolean;
  lookalike: { brand: string; technique: string; confidence: number; detail: string } | null;
  homoglyph: { scripts: string[]; mixedScript: boolean; skeleton: string } | null;
}

export class ThreatIntelService {
  readonly providers: ThreatIntelProvider[];
  private readonly cache = new Map<string, { at: number; result: ThreatIntelResult }>();

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    providers?: ThreatIntelProvider[],
  ) {
    this.providers = providers ?? [
      virusTotalProvider(config.VIRUSTOTAL_API_KEY),
      abuseIpDbProvider(config.ABUSEIPDB_API_KEY),
      urlScanProvider(config.URLSCAN_API_KEY),
      safeBrowsingProvider(config.GOOGLE_SAFE_BROWSING_API_KEY),
      rdapProvider(config.RDAP_ENABLED),
    ];
  }

  get anyConfigured(): boolean {
    return this.providers.some((p) => p.configured);
  }

  /** Query every provider that supports `kind`. Unconfigured providers are reported, never contacted. */
  async lookup(kind: TargetKind, target: string): Promise<ThreatIntelResult[]> {
    const relevant = this.providers.filter((p) => p.kinds.includes(kind));
    return Promise.all(
      relevant.map(async (provider) => {
        if (!provider.configured) {
          return {
            provider: provider.name,
            target,
            status: 'not_configured',
            summary: `${provider.name} is not configured`,
          } satisfies ThreatIntelResult;
        }
        const key = `${provider.name}|${kind}|${target}`;
        const cached = this.cache.get(key);
        if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.result;
        try {
          const result = await provider.lookup(
            kind,
            target,
            AbortSignal.timeout(this.config.THREAT_INTEL_TIMEOUT_MS),
          );
          if (this.cache.size >= CACHE_MAX) this.cache.delete(this.cache.keys().next().value!);
          this.cache.set(key, { at: Date.now(), result });
          this.logger.info(
            {
              event: 'enrichment.completed',
              provider: provider.name,
              kind,
              verdict: result.verdict,
            },
            'external enrichment completed',
          );
          return result;
        } catch (error) {
          this.logger.warn(
            {
              event: 'enrichment.failed',
              provider: provider.name,
              kind,
              error: error instanceof Error ? error.message : 'unknown',
            },
            'external enrichment failed',
          );
          return {
            provider: provider.name,
            target,
            status: 'error',
            summary: `Lookup failed: ${error instanceof Error ? error.message : 'unknown error'}`,
          } satisfies ThreatIntelResult;
        }
      }),
    );
  }

  /** Enrich the indicators of one analysis. Returns nothing if no provider is configured. */
  async enrich(targets: {
    domains: string[];
    ips: string[];
  }): Promise<{ results: ThreatIntelResult[]; findings: Omit<Finding, 'id'>[] }> {
    if (!this.anyConfigured) return { results: [], findings: [] };
    const domains = [...new Set(targets.domains)].filter(Boolean).slice(0, MAX_ENRICH_TARGETS);
    const ips = [...new Set(targets.ips)].filter((ip) => net.isIP(ip)).slice(0, 2);
    const batches = await Promise.all([
      ...domains.map((d) => this.lookup('domain', d)),
      ...ips.map((ip) => this.lookup('ip', ip)),
    ]);
    const results = batches.flat().filter((r) => r.status !== 'not_configured');
    const findings = results
      .filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious')
      .map((r): Omit<Finding, 'id'> => ({
        detector: `threat_intel.${r.provider.toLowerCase().replace(/\W+/g, '_')}`,
        category: 'threat_intel',
        source: 'threat_intel',
        severity: r.verdict === 'malicious' ? 'critical' : 'medium',
        confidence: r.verdict === 'malicious' ? 0.9 : 0.6,
        title: `${r.provider}: ${r.target} reported ${r.verdict}`,
        description: r.summary ?? '',
        whyItMatters:
          'Independent external reputation data corroborates or contradicts the local analysis.',
        evidence: [
          { label: 'Provider', value: r.provider },
          { label: 'Indicator', value: r.target },
          ...(r.summary ? [{ label: 'Result', value: r.summary }] : []),
        ],
        recommendation:
          r.verdict === 'malicious'
            ? 'Block the indicator across mail and web gateways.'
            : 'Monitor; corroborate with local evidence.',
        method: `Queried ${r.provider} for the indicator.`,
        scoreGroup: 'threat_intel',
      }));
    return { results, findings };
  }

  localDomainIntel(domain: string): LocalDomainIntel {
    const info = domainInfo(domain);
    const lookalike = assessLookalike(domain);
    const homoglyph = assessHomoglyph(domain);
    const tld = info.publicSuffix.split('.').pop() ?? '';
    return {
      domain: info.host,
      registrableDomain: info.registrable,
      unicodeDomain: info.unicodeHost,
      publicSuffix: info.publicSuffix,
      officialBrand: brandForOfficialDomain(info.registrable)?.name ?? null,
      freeMailProvider: FREE_MAIL_DOMAINS.has(info.registrable),
      urlShortener: URL_SHORTENERS.has(info.registrable),
      suspiciousTld: SUSPICIOUS_TLDS.has(tld),
      lookalike: lookalike
        ? {
            brand: lookalike.brand.name,
            technique: lookalike.technique,
            confidence: lookalike.confidence,
            detail: lookalike.detail,
          }
        : null,
      homoglyph: homoglyph
        ? {
            scripts: homoglyph.scripts,
            mixedScript: homoglyph.mixedScript,
            skeleton: homoglyph.skeleton,
          }
        : null,
    };
  }
}
