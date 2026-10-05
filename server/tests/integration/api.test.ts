import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { fakeMl, fixture, sample, testContext } from '../helpers.js';

type Ctx = Awaited<ReturnType<typeof testContext>>;
let ctx: Ctx;
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  ctx = await testContext(fakeMl(), { MAX_EMAIL_BYTES: '65536' });
  app = createApp(ctx);
});
afterAll(async () => {
  await ctx.db.destroy();
});

const upload = (name: string, body: Buffer = sample(name)) =>
  request(app).post('/api/analyze').attach('email', body, name.split('/').pop()!);

describe('POST /api/analyze', () => {
  it('analyses an uploaded .eml and returns the structured verdict', async () => {
    const res = await upload('phishing/paypal-alert.eml').expect(201);
    expect(res.body).toMatchObject({
      success: true,
      riskLevel: expect.any(String),
      classification: 'phishing',
    });
    expect(res.body.analysisId).toMatch(/^an_/);
    expect(res.body.riskScore).toBeGreaterThanOrEqual(60);
    expect(res.body.findings.length).toBeGreaterThan(3);
    expect(res.body.analysis.ml).toEqual({
      available: false,
      reason: 'ML service is not reachable',
    });
  });

  it('streams real pipeline stages over Server-Sent Events', async () => {
    const res = await upload('legitimate/normal-newsletter.eml')
      .set('Accept', 'text/event-stream')
      .expect(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    const events = res.text
      .split('\n\n')
      .filter(Boolean)
      .map((block) => JSON.parse(block.split('\ndata: ')[1]!));
    expect(events.filter((e) => e.type === 'stage').map((e) => e.stage.id)).toContain('rules');
    expect(events.at(-1).type).toBe('result');
    expect(events.at(-1).analysis.risk.classification).toBe('legitimate');
  });

  it('rejects missing files, unsupported formats and oversized uploads', async () => {
    expect((await request(app).post('/api/analyze').expect(400)).body.error.code).toBe(
      'missing_file',
    );
    expect((await upload('message.msg', Buffer.from('x')).expect(400)).body.error.code).toBe(
      'unsupported_format',
    );
    expect((await upload('payload.exe', Buffer.from('MZ')).expect(400)).body.error.code).toBe(
      'unsupported_file',
    );
    expect((await upload('big.eml', Buffer.alloc(70_000, 'a')).expect(413)).body.error.code).toBe(
      'payload_too_large',
    );
  });

  it('reports non-email content clearly without storing anything', async () => {
    const before = (await request(app).get('/api/analyses')).body.total;
    const res = await upload('notes.eml', Buffer.from('this is not an email')).expect(422);
    expect(res.body.error.code).toBe('not_an_email');
    expect((await request(app).get('/api/analyses')).body.total).toBe(before);
  });

  it('returns a streamed error event for unparseable input', async () => {
    const res = await upload('notes.eml', Buffer.from('nope'))
      .set('Accept', 'text/event-stream')
      .expect(200);
    expect(res.text).toContain('event: error');
    expect(res.text).toContain('not_an_email');
  });

  it('does not let hostile HTML reach the client unsanitised', async () => {
    const res = await upload('xss.eml', fixture('xss-html.eml')).expect(201);
    expect(res.body.analysis.body.sanitizedHtml).not.toMatch(/<script|onerror|<iframe|<img/i);
  });
});

describe('POST /api/analyze/raw', () => {
  it('analyses pasted email content', async () => {
    const res = await request(app)
      .post('/api/analyze/raw')
      .send({ raw: sample('phishing/delivery-scam.eml').toString('utf8') })
      .expect(201);
    expect(res.body.classification).toBe('phishing');
    expect(res.body.analysis.sourceName).toBe('Pasted email');
  });

  it('validates the request body', async () => {
    const res = await request(app).post('/api/analyze/raw').send({ raw: '' }).expect(400);
    expect(res.body.error.code).toBe('validation_failed');
    await request(app)
      .post('/api/analyze/raw')
      .set('content-type', 'application/json')
      .send('{bad json')
      .expect(400);
  });
});

describe('investigation history', () => {
  let id: string;
  beforeAll(async () => {
    id = (await upload('phishing/fake-invoice.eml')).body.analysisId;
    await upload('legitimate/legitimate-invoice.eml');
  });

  it('lists, searches, filters, sorts and paginates', async () => {
    const all = await request(app)
      .get('/api/analyses?pageSize=2&sort=risk_score&order=desc')
      .expect(200);
    expect(all.body.items).toHaveLength(2);
    expect(all.body.total).toBeGreaterThanOrEqual(4);
    expect(all.body.items[0].riskScore).toBeGreaterThanOrEqual(all.body.items[1].riskScore);

    const search = await request(app).get('/api/analyses?search=INV-20931').expect(200);
    expect(search.body.items.map((i: { id: string }) => i.id)).toContain(id);

    const legit = await request(app).get('/api/analyses?classification=legitimate').expect(200);
    expect(
      legit.body.items.every((i: { classification: string }) => i.classification === 'legitimate'),
    ).toBe(true);

    const critical = await request(app).get('/api/analyses?riskLevel=critical,high').expect(200);
    expect(
      critical.body.items.every((i: { riskLevel: string }) =>
        ['critical', 'high'].includes(i.riskLevel),
      ),
    ).toBe(true);
  });

  it('treats LIKE wildcards in search literally', async () => {
    const res = await request(app).get('/api/analyses?search=%25').expect(200);
    expect(res.body.total).toBe(0);
  });

  it('rejects invalid filters', async () => {
    await request(app).get('/api/analyses?riskLevel=extreme').expect(400);
    await request(app).get('/api/analyses?sort=password').expect(400);
  });

  it('returns a full analysis, its raw source and a report', async () => {
    const res = await request(app).get(`/api/analyses/${id}`).expect(200);
    expect(res.body.analysis.attachments[0].filename).toBe('INV-20931.pdf.exe');
    const raw = await request(app).get(`/api/analyses/${id}/raw`).expect(200);
    expect(raw.headers['content-type']).toContain('text/plain');
    expect(raw.headers['x-content-type-options']).toBe('nosniff');
    expect(raw.text).toContain('Subject: Overdue invoice');
    const report = await request(app).get(`/api/analyses/${id}/report`).expect(200);
    expect(report.headers['content-disposition']).toContain('attachment');
    expect(report.body.iocs.attachmentHashes[0].sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('handles unknown and malformed ids', async () => {
    await request(app).get('/api/analyses/an_doesnotexist0').expect(404);
    await request(app).get('/api/analyses/..%2F..%2Fetc').expect(400);
  });

  it('records analyst feedback and reflects it in history and stats', async () => {
    await request(app)
      .post('/api/feedback')
      .send({ analysisId: id, verdict: 'false_positive', notes: 'test' })
      .expect(201);
    const res = await request(app).get(`/api/analyses/${id}`).expect(200);
    expect(res.body.analysis.feedback.verdict).toBe('false_positive');
    const stats = await request(app).get('/api/stats').expect(200);
    expect(stats.body.totals.falsePositives).toBe(1);
    await request(app).post('/api/feedback').send({ analysisId: id, verdict: 'maybe' }).expect(400);
    await request(app)
      .post('/api/feedback')
      .send({ analysisId: 'an_missing000000', verdict: 'uncertain' })
      .expect(404);
  });

  it('computes dashboard statistics from stored investigations', async () => {
    const stats = (await request(app).get('/api/stats').expect(200)).body;
    const total = stats.totals.investigations;
    expect(total).toBe(
      stats.classification.phishing +
        stats.classification.suspicious +
        stats.classification.legitimate,
    );
    expect(
      Object.values(stats.riskDistribution as Record<string, number>).reduce((a, b) => a + b, 0),
    ).toBe(total);
    expect(stats.history).toHaveLength(30);
    expect(stats.history.at(-1).total).toBe(total);
  });

  it('deletes an investigation and its findings', async () => {
    const victim = (await upload('phishing/delivery-scam.eml')).body.analysisId;
    await request(app).delete(`/api/analyses/${victim}`).expect(200);
    await request(app).get(`/api/analyses/${victim}`).expect(404);
    await request(app).delete(`/api/analyses/${victim}`).expect(404);
  });
});

describe('system endpoints', () => {
  it('reports real component health including ML being offline', async () => {
    const res = await request(app).get('/api/health').expect(200);
    expect(res.body.status).toBe('degraded');
    expect(res.body.components.database.status).toBe('up');
    expect(res.body.components.ml.status).toBe('down');
    expect(res.body.components.threatIntel.VirusTotal.status).toBe('not_configured');
  });

  it('serves model metadata from artifacts when the ML service is down', async () => {
    const res = await request(app).get('/api/model').expect(200);
    if (res.body.available) {
      expect(res.body.source).toBe('artifacts');
      expect(res.body.metadata.model_version).toBeDefined();
      expect(res.body.metrics.test.confusion_matrix).toBeDefined();
    }
  });

  it('performs local threat intelligence without contacting unconfigured providers', async () => {
    const res = await request(app).get('/api/threat-intel/paypa1.com').expect(200);
    expect(res.body.local.lookalike.brand).toBe('PayPal');
    expect(res.body.external.every((r: { status: string }) => r.status === 'not_configured')).toBe(
      true,
    );
    await request(app).get('/api/threat-intel/not_a_domain').expect(400);
  });

  it('serves sample emails and blocks path traversal', async () => {
    const list = await request(app).get('/api/samples').expect(200);
    expect(list.body.samples.length).toBeGreaterThanOrEqual(10);
    await request(app).get('/api/samples/phishing/paypal-alert.eml').expect(200);
    await request(app).get('/api/samples/phishing/..%2F..%2F.env').expect(400);
    await request(app).get('/api/samples/..%2Fserver/package.json').expect(400);
  });

  it('sets security headers and hides framework details', async () => {
    const res = await request(app).get('/api/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('returns JSON 404s for unknown endpoints', async () => {
    const res = await request(app).get('/api/does-not-exist').expect(404);
    expect(res.body.error.code).toBe('not_found');
  });
});
