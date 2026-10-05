import type { Db } from '../db/database.js';
import type { AnalystFeedback, FeedbackVerdict } from '../models/analysis.js';

export class FeedbackRepository {
  constructor(private readonly db: Db) {}

  async add(
    analysisId: string,
    verdict: FeedbackVerdict,
    notes?: string,
  ): Promise<AnalystFeedback> {
    const createdAt = new Date().toISOString();
    await this.db
      .insertInto('feedback')
      .values({
        analysis_id: analysisId,
        verdict,
        notes: notes ?? null,
        created_at: createdAt,
        reviewed: 0,
      })
      .execute();
    return { verdict, notes, createdAt };
  }
}
