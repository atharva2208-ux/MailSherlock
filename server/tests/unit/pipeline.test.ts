import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../../src/config/env.js';
import { analyzeEmail } from '../../src/services/analysisPipeline.js';
import { fakeMl, sample, testContext } from '../helpers.js';

type Ctx = Awaited<ReturnType<typeof testContext>>;
let ctx: Ctx;
const run = (name: string) =>
  analyzeEmail(
    {
      config: ctx.config,
      logger: ctx.logger,
      repository: ctx.analyses,
      ml: ctx.ml,
      threatIntel: ctx.threatIntel,
    },
    { raw: sample(name), sourceName: name },
  );

beforeAll(async () => {
  ctx = await testContext(fakeMl());
});
afterAll(async () => {
  await ctx.db.destroy();
});

describe('end-to-end detection on the sample corpus (rule engine only)', () => {
  const list = (label: string) =>
    fs
      .readdirSync(path.join(REPO_ROOT, 'samples', label))
      .filter((f) => f.endsWith('.eml'))
      .map((f) => `${label}/${f}`);

  it.each(list('phishing'))('%s is classified as phishing', async (name) => {
    const result = await run(name);
    expect(result.risk.classification).toBe('phishing');
    expect(result.ml.available).toBe(false);
    expect(result.stages.find((s) => s.id === 'ml')?.status).toBe('skipped');
  });

  it.each(list('legitimate'))('%s is classified as legitimate', async (name) => {
    const result = await run(name);
    expect(result.risk.classification).toBe('legitimate');
    expect(result.risk.trustedContext).toBe(true);
  });

  it('produces the expected evidence for the Microsoft lookalike sample', async () => {
    const result = await run('phishing/microsoft-account.eml');
    const detectors = result.findings.map((f) => f.detector);
    expect(detectors).toEqual(
      expect.arrayContaining([
        'auth.dmarc',
        'auth.spf',
        'impersonation.lookalike_sender',
        'url.anchor_mismatch',
        'header.reply_to_mismatch',
        'content.credential_request',
      ]),
    );
    expect(result.authentication.dmarc.state).toBe('fail');
    const urgency = result.findings.find((f) => f.detector === 'content.urgency');
    expect(urgency?.spans?.some((s) => /within 24 hours/i.test(s.text))).toBe(true);
  });

  it('records real stage timings for every pipeline stage', async () => {
    const result = await run('legitimate/normal-newsletter.eml');
    expect(result.stages.map((s) => s.id)).toEqual([
      'parse',
      'headers',
      'authentication',
      'urls',
      'content',
      'attachments',
      'rules',
      'ml',
      'threat_intel',
      'correlation',
      'scoring',
      'persist',
    ]);
    expect(result.stages.find((s) => s.id === 'threat_intel')?.status).toBe('skipped');
  });

  it('uses the ML model as corroborating evidence when available', async () => {
    const withMl = await testContext(
      fakeMl({
        available: true,
        probability: 0.97,
        threshold: 0.55,
        label: 'phishing',
        confidence: 'high',
        modelVersion: '1.0.0',
        signals: [],
      }),
    );
    const result = await analyzeEmail(
      {
        config: withMl.config,
        logger: withMl.logger,
        repository: withMl.analyses,
        ml: withMl.ml,
        threatIntel: withMl.threatIntel,
      },
      { raw: sample('legitimate/legitimate-password-reset.eml'), sourceName: 'x' },
    );
    // A trusted sender keeps a confident-but-wrong ML prediction from causing a false positive.
    expect(result.risk.classification).toBe('legitimate');
    expect(result.risk.contributions.find((c) => c.kind === 'ml')?.detail).toContain(
      'authenticated',
    );
    await withMl.db.destroy();
  });
});
