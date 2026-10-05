import type { Request, Response } from 'express';
import { notFound } from '../utils/errors.js';
import { feedbackSchema } from '../validators/schemas.js';
import type { AppContext } from './context.js';

export function feedbackController(ctx: AppContext) {
  return {
    async submit(req: Request, res: Response) {
      const body = feedbackSchema.parse(req.body);
      if (!(await ctx.analyses.exists(body.analysisId))) throw notFound('Investigation not found');
      const feedback = await ctx.feedback.add(body.analysisId, body.verdict, body.notes);
      ctx.logger.info(
        { event: 'feedback.recorded', analysisId: body.analysisId, verdict: body.verdict },
        'analyst feedback recorded',
      );
      res.status(201).json({ success: true, feedback });
    },
  };
}
