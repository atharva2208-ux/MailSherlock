import type { Request, Response } from 'express';
import type { AnalysisEvent } from '../models/analysis.js';
import { toApiError } from '../middleware/errorHandler.js';
import { analyzeEmail } from '../services/analysisPipeline.js';
import { buildReport } from '../services/reporting/report.js';
import { sanitiseFilename } from '../services/analyzers/attachments.js';
import { badRequest, notFound, payloadTooLarge } from '../utils/errors.js';
import { analysisIdSchema, listQuerySchema, rawAnalyzeSchema } from '../validators/schemas.js';
import type { AppContext } from './context.js';

function wantsStream(req: Request): boolean {
  return (req.headers.accept ?? '').includes('text/event-stream');
}

function sendEvent(res: Response, event: AnalysisEvent) {
  res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
}

/**
 * Runs an analysis and answers either with JSON or, when the client sends
 * `Accept: text/event-stream`, with Server-Sent Events carrying each real
 * pipeline stage as it completes followed by the result.
 */
async function respondWithAnalysis(
  ctx: AppContext,
  req: Request,
  res: Response,
  raw: Buffer,
  sourceName: string,
) {
  const deps = {
    config: ctx.config,
    logger: ctx.logger,
    repository: ctx.analyses,
    ml: ctx.ml,
    threatIntel: ctx.threatIntel,
  };
  if (!wantsStream(req)) {
    const analysis = await analyzeEmail(deps, { raw, sourceName });
    res.status(201).json({
      success: true,
      analysisId: analysis.id,
      riskScore: analysis.risk.score,
      riskLevel: analysis.risk.level,
      classification: analysis.risk.classification,
      findings: analysis.findings,
      analysis,
    });
    return;
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  try {
    const analysis = await analyzeEmail(deps, {
      raw,
      sourceName,
      onEvent: (event) => sendEvent(res, event),
    });
    sendEvent(res, { type: 'result', analysis });
  } catch (error) {
    const { body } = toApiError(error, ctx.config.MAX_EMAIL_BYTES);
    if (body.code === 'internal_error')
      ctx.logger.error(
        { event: 'error', err: error instanceof Error ? error.message : String(error) },
        'streamed analysis failed',
      );
    sendEvent(res, { type: 'error', error: body });
  }
  res.end();
}

export function analysisController(ctx: AppContext) {
  return {
    async analyzeUpload(req: Request, res: Response) {
      if (!req.file)
        throw badRequest('missing_file', 'Attach an .eml file in the "email" form field.');
      await respondWithAnalysis(
        ctx,
        req,
        res,
        req.file.buffer,
        sanitiseFilename(req.file.originalname),
      );
    },

    async analyzeRaw(req: Request, res: Response) {
      const body = rawAnalyzeSchema.parse(req.body);
      const raw = Buffer.from(body.raw, 'utf8');
      if (raw.length > ctx.config.MAX_EMAIL_BYTES)
        throw payloadTooLarge(ctx.config.MAX_EMAIL_BYTES);
      await respondWithAnalysis(
        ctx,
        req,
        res,
        raw,
        body.sourceName ? sanitiseFilename(body.sourceName) : 'Pasted email',
      );
    },

    async list(req: Request, res: Response) {
      const query = listQuerySchema.parse(req.query);
      res.json({ success: true, ...(await ctx.analyses.list(query)) });
    },

    async get(req: Request, res: Response) {
      const id = analysisIdSchema.parse(req.params.id);
      const analysis = await ctx.analyses.get(id);
      if (!analysis) throw notFound('Investigation not found');
      res.json({ success: true, analysis });
    },

    async raw(req: Request, res: Response) {
      const id = analysisIdSchema.parse(req.params.id);
      const raw = await ctx.analyses.getRaw(id);
      if (raw === undefined) throw notFound('Investigation not found');
      if (raw === null)
        throw notFound(
          'Raw source was not retained for this investigation (STORE_RAW_SOURCE=false)',
        );
      // Served as inert text with sniffing disabled so a browser can never render it.
      res.type('text/plain; charset=utf-8').setHeader('X-Content-Type-Options', 'nosniff');
      res.send(raw);
    },

    async report(req: Request, res: Response) {
      const id = analysisIdSchema.parse(req.params.id);
      const analysis = await ctx.analyses.get(id);
      if (!analysis) throw notFound('Investigation not found');
      res.setHeader('Content-Disposition', `attachment; filename="mailsherlock-${id}.json"`);
      res.json(buildReport(analysis));
    },

    async remove(req: Request, res: Response) {
      const id = analysisIdSchema.parse(req.params.id);
      if (!(await ctx.analyses.delete(id))) throw notFound('Investigation not found');
      ctx.logger.info({ event: 'analysis.deleted', analysisId: id }, 'analysis deleted');
      res.json({ success: true });
    },
  };
}
