import { sql } from 'kysely';
import type { Db } from '../db/database.js';
import type {
  AnalysisResult,
  AnalysisSummary,
  Classification,
  DashboardStats,
  FeedbackVerdict,
  FindingCategory,
  Paginated,
  RiskLevel,
  Severity,
} from '../models/analysis.js';
import type { ListQuery } from '../validators/schemas.js';

const escapeLike = (value: string) => value.replace(/[\\%_]/g, (c) => `\\${c}`);

export class AnalysisRepository {
  constructor(private readonly db: Db) {}

  async insert(result: AnalysisResult, rawSource: string | null): Promise<void> {
    const severityCount = (s: Severity) => result.findings.filter((f) => f.severity === s).length;
    await this.db.transaction().execute(async (trx) => {
      await trx
        .insertInto('analyses')
        .values({
          id: result.id,
          created_at: result.createdAt,
          source_name: result.sourceName,
          sender_address: result.metadata.from?.address ?? '',
          sender_domain: result.metadata.from?.domain ?? '',
          subject: result.metadata.subject,
          risk_score: result.risk.score,
          risk_level: result.risk.level,
          classification: result.risk.classification,
          finding_count: result.findings.length,
          critical_count: severityCount('critical'),
          high_count: severityCount('high'),
          ml_probability: result.ml.available ? (result.ml.probability ?? null) : null,
          model_version: result.ml.available ? (result.ml.modelVersion ?? null) : null,
          message_sha256: result.sha256,
          size_bytes: result.sizeBytes,
          engine_version: result.engineVersion,
          result_json: JSON.stringify(result),
          raw_source: rawSource,
        })
        .execute();
      if (result.findings.length) {
        await trx
          .insertInto('findings')
          .values(
            result.findings.map((f) => ({
              analysis_id: result.id,
              detector: f.detector,
              category: f.category,
              severity: f.severity,
              title: f.title,
              created_at: result.createdAt,
            })),
          )
          .execute();
      }
    });
  }

  async get(id: string): Promise<AnalysisResult | null> {
    const row = await this.db
      .selectFrom('analyses')
      .select('result_json')
      .where('id', '=', id)
      .executeTakeFirst();
    if (!row) return null;
    const result = JSON.parse(row.result_json) as AnalysisResult;
    const feedback = await this.db
      .selectFrom('feedback')
      .select(['verdict', 'notes', 'created_at'])
      .where('analysis_id', '=', id)
      .orderBy('id', 'desc')
      .executeTakeFirst();
    if (feedback)
      result.feedback = {
        verdict: feedback.verdict as FeedbackVerdict,
        notes: feedback.notes ?? undefined,
        createdAt: feedback.created_at,
      };
    return result;
  }

  async getRaw(id: string): Promise<string | null | undefined> {
    const row = await this.db
      .selectFrom('analyses')
      .select('raw_source')
      .where('id', '=', id)
      .executeTakeFirst();
    return row ? row.raw_source : undefined;
  }

  async exists(id: string): Promise<boolean> {
    return Boolean(
      await this.db.selectFrom('analyses').select('id').where('id', '=', id).executeTakeFirst(),
    );
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.db.deleteFrom('analyses').where('id', '=', id).executeTakeFirst();
    return Number(result.numDeletedRows) > 0;
  }

  async list(query: ListQuery): Promise<Paginated<AnalysisSummary>> {
    let base = this.db.selectFrom('analyses');
    const search = query.search;
    if (search) {
      const term = `%${escapeLike(search.toLowerCase())}%`;
      base = base.where((eb) =>
        eb.or([
          eb(sql`lower(subject)`, 'like', sql`${term} escape '\\'`),
          eb(sql`lower(sender_address)`, 'like', sql`${term} escape '\\'`),
          eb(sql`lower(source_name)`, 'like', sql`${term} escape '\\'`),
          eb('id', '=', search),
          eb('message_sha256', '=', search.toLowerCase()),
        ]),
      );
    }
    if (query.riskLevel.length) base = base.where('risk_level', 'in', query.riskLevel);
    if (query.classification.length)
      base = base.where('classification', 'in', query.classification);
    if (query.from) base = base.where('created_at', '>=', new Date(query.from).toISOString());
    if (query.to) {
      const end =
        query.to.length === 10 ? new Date(Date.parse(query.to) + 86_400_000) : new Date(query.to);
      base = base.where('created_at', '<', end.toISOString());
    }

    const { total } = await base
      .select((eb) => eb.fn.countAll<number>().as('total'))
      .executeTakeFirstOrThrow();
    const rows = await base
      .select([
        'analyses.id',
        'analyses.created_at',
        'source_name',
        'sender_address',
        'sender_domain',
        'subject',
        'risk_score',
        'risk_level',
        'classification',
        'finding_count',
        'critical_count',
        'high_count',
        'ml_probability',
        'model_version',
        (eb) =>
          eb
            .selectFrom('feedback')
            .select('verdict')
            .whereRef('feedback.analysis_id', '=', 'analyses.id')
            .orderBy('feedback.id', 'desc')
            .limit(1)
            .as('feedback_verdict'),
      ])
      .orderBy(query.sort, query.order)
      .orderBy('analyses.id', 'desc')
      .limit(query.pageSize)
      .offset((query.page - 1) * query.pageSize)
      .execute();

    return {
      total: Number(total),
      page: query.page,
      pageSize: query.pageSize,
      items: rows.map((r) => ({
        id: r.id,
        createdAt: r.created_at,
        sourceName: r.source_name,
        sender: r.sender_address,
        senderDomain: r.sender_domain,
        subject: r.subject,
        riskScore: r.risk_score,
        riskLevel: r.risk_level as RiskLevel,
        classification: r.classification as Classification,
        findingCount: r.finding_count,
        criticalCount: r.critical_count,
        highCount: r.high_count,
        mlProbability: r.ml_probability,
        modelVersion: r.model_version,
        feedback: (r.feedback_verdict as FeedbackVerdict | null) ?? null,
      })),
    };
  }

  async stats(historyDays = 30): Promise<DashboardStats> {
    const byClass = await this.db
      .selectFrom('analyses')
      .select(['classification', (eb) => eb.fn.countAll<number>().as('n')])
      .groupBy('classification')
      .execute();
    const byLevel = await this.db
      .selectFrom('analyses')
      .select(['risk_level', (eb) => eb.fn.countAll<number>().as('n')])
      .groupBy('risk_level')
      .execute();
    const categories = await this.db
      .selectFrom('findings')
      .select(['category', (eb) => eb.fn.countAll<number>().as('n')])
      .where('severity', '!=', 'info')
      .groupBy('category')
      .orderBy('n', 'desc')
      .execute();
    const indicators = await this.db
      .selectFrom('findings')
      .select(['title', (eb) => eb.fn.countAll<number>().as('n')])
      .where('severity', '!=', 'info')
      .groupBy('title')
      .orderBy('n', 'desc')
      .limit(8)
      .execute();
    const criticalFindings = await this.db
      .selectFrom('findings')
      .select((eb) => eb.fn.countAll<number>().as('n'))
      .where('severity', '=', 'critical')
      .executeTakeFirstOrThrow();

    const since = new Date(Date.now() - (historyDays - 1) * 86_400_000);
    since.setUTCHours(0, 0, 0, 0);
    const daily = await this.db
      .selectFrom('analyses')
      .select([
        sql<string>`substr(created_at, 1, 10)`.as('day'),
        'classification',
        (eb) => eb.fn.countAll<number>().as('n'),
      ])
      .where('created_at', '>=', since.toISOString())
      .groupBy(['day', 'classification'])
      .execute();

    // Latest feedback per analysis decides how it counts.
    const feedback = await this.db
      .selectFrom('feedback as f')
      .select(['f.verdict'])
      .where('f.id', 'in', (eb) =>
        eb
          .selectFrom('feedback')
          .select((e) => e.fn.max('id').as('id'))
          .groupBy('analysis_id'),
      )
      .execute();

    const classification: Record<Classification, number> = {
      phishing: 0,
      suspicious: 0,
      legitimate: 0,
    };
    for (const row of byClass) classification[row.classification as Classification] = Number(row.n);
    const riskDistribution: Record<RiskLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      safe: 0,
    };
    for (const row of byLevel) riskDistribution[row.risk_level as RiskLevel] = Number(row.n);

    const history: DashboardStats['history'] = [];
    for (let i = 0; i < historyDays; i++) {
      const date = new Date(since.getTime() + i * 86_400_000).toISOString().slice(0, 10);
      const rows = daily.filter((d) => d.day === date);
      const count = (c: Classification) => Number(rows.find((r) => r.classification === c)?.n ?? 0);
      history.push({
        date,
        phishing: count('phishing'),
        suspicious: count('suspicious'),
        legitimate: count('legitimate'),
        total: rows.reduce((s, r) => s + Number(r.n), 0),
      });
    }

    // Severity is stored as text, so rank it explicitly rather than relying on string ordering.
    const severityRank: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const worstFor = async (title: string): Promise<Severity> => {
      const rows = await this.db
        .selectFrom('findings')
        .select('severity')
        .distinct()
        .where('title', '=', title)
        .execute();
      return severityRank.find((s) => rows.some((r) => r.severity === s)) ?? 'info';
    };

    return {
      totals: {
        investigations: Object.values(classification).reduce((a, b) => a + b, 0),
        threats: classification.phishing,
        suspicious: classification.suspicious,
        criticalFindings: Number(criticalFindings.n),
        highRisk: riskDistribution.critical + riskDistribution.high,
        falsePositives: feedback.filter((f) => f.verdict === 'false_positive').length,
        feedbackCount: feedback.length,
      },
      classification,
      riskDistribution,
      categories: categories.map((c) => ({
        category: c.category as FindingCategory,
        count: Number(c.n),
      })),
      history,
      topIndicators: await Promise.all(
        indicators.map(async (i) => ({
          title: i.title,
          count: Number(i.n),
          severity: await worstFor(i.title),
        })),
      ),
    };
  }
}
