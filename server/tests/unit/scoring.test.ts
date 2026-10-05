import { describe, expect, it } from 'vitest';
import type { Finding, MlAssessment } from '../../src/models/analysis.js';
import type { TrustContext } from '../../src/services/scoring/correlation.js';
import { applyTrustAdjustments } from '../../src/services/scoring/correlation.js';
import {
  classificationFor,
  levelFor,
  ML_SOLO_CAP,
  normaliseScore,
  scoreRisk,
} from '../../src/services/scoring/riskScore.js';

const finding = (overrides: Partial<Finding>): Finding => ({
  id: 'f1',
  detector: 'test',
  category: 'url',
  severity: 'high',
  confidence: 1,
  title: 'Test',
  description: '',
  whyItMatters: '',
  evidence: [],
  recommendation: '',
  source: 'rule',
  method: '',
  scoreGroup: 'url',
  ...overrides,
});
const untrusted: TrustContext = { trusted: false, reasons: [], blockers: ['x'] };
const trusted: TrustContext = { trusted: true, reasons: ['DMARC pass'], blockers: [] };
const noMl: MlAssessment = { available: false, reason: 'offline' };
const ml = (probability: number, confidence: 'high' | 'low' = 'high'): MlAssessment => ({
  available: true,
  probability,
  threshold: 0.55,
  label: probability >= 0.55 ? 'phishing' : 'legitimate',
  confidence,
});

describe('risk scoring', () => {
  it('maps scores to levels and classifications', () => {
    expect([levelFor(85), levelFor(60), levelFor(45), levelFor(25), levelFor(5)]).toEqual([
      'critical',
      'high',
      'medium',
      'low',
      'safe',
    ]);
    expect([classificationFor(60), classificationFor(35), classificationFor(34)]).toEqual([
      'phishing',
      'suspicious',
      'legitimate',
    ]);
  });

  it('normalises monotonically onto 0-100', () => {
    expect(normaliseScore(0)).toBe(0);
    expect(normaliseScore(60)).toBeLessThan(normaliseScore(100));
    expect(normaliseScore(1000)).toBeLessThanOrEqual(100);
  });

  it('applies diminishing returns and caps within a correlated group', () => {
    const one = scoreRisk([finding({})], noMl, untrusted);
    const many = scoreRisk(
      Array.from({ length: 10 }, (_, i) => finding({ id: `f${i}` })),
      noMl,
      untrusted,
    );
    expect(many.ruleScore).toBeLessThanOrEqual(40); // url group cap
    expect(many.ruleScore).toBeLessThan(one.ruleScore * 10);
  });

  it('rewards independent corroborating evidence across categories', () => {
    const findings = [
      finding({ category: 'url', scoreGroup: 'url' }),
      finding({ category: 'authentication', scoreGroup: 'authentication' }),
      finding({ category: 'content', scoreGroup: 'content' }),
    ];
    expect(
      scoreRisk(findings, noMl, untrusted).contributions.some((c) => c.kind === 'correlation'),
    ).toBe(true);
  });

  it('does not let the ML model raise a verdict on its own', () => {
    const result = scoreRisk([], ml(0.99), untrusted);
    const mlPoints = result.contributions.find((c) => c.kind === 'ml')!.points;
    expect(mlPoints).toBeLessThanOrEqual(ML_SOLO_CAP);
    expect(result.classification).toBe('legitimate');
  });

  it('damps ML for trusted senders and for low-confidence predictions', () => {
    const evidence = [finding({ severity: 'medium' })];
    const base = scoreRisk(evidence, ml(0.95), untrusted).contributions.find(
      (c) => c.kind === 'ml',
    )!.points;
    expect(
      scoreRisk(evidence, ml(0.95), trusted).contributions.find((c) => c.kind === 'ml')!.points,
    ).toBeLessThan(base);
    expect(
      scoreRisk(evidence, ml(0.95, 'low'), untrusted).contributions.find((c) => c.kind === 'ml')!
        .points,
    ).toBeLessThan(base);
  });

  it('enforces a floor for a single high-confidence critical indicator', () => {
    const result = scoreRisk(
      [finding({ severity: 'critical', confidence: 0.97, scoreGroup: 'credential_form' })],
      noMl,
      untrusted,
    );
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.classification).toBe('phishing');
  });

  it('works without ML (rule-only fallback)', () => {
    const result = scoreRisk([finding({})], noMl, untrusted);
    expect(result.contributions.every((c) => c.kind !== 'ml')).toBe(true);
    expect(result.summary).not.toContain('ML');
  });
});

describe('trust adjustments', () => {
  it('downgrades transactional language from authenticated senders but leaves other evidence', () => {
    const findings = [
      finding({ category: 'content', detector: 'content.credential_request', severity: 'high' }),
      finding({ category: 'content', detector: 'content.financial_request', severity: 'high' }),
      finding({ category: 'url', detector: 'url.ip_host', severity: 'high' }),
    ];
    const adjusted = applyTrustAdjustments(findings, trusted);
    expect(adjusted[0]).toMatchObject({ severity: 'low', adjustment: { from: 'high', to: 'low' } });
    expect(adjusted[1]!.severity).toBe('high');
    expect(adjusted[2]!.severity).toBe('high');
    expect(applyTrustAdjustments(findings, untrusted)).toBe(findings);
  });
});
