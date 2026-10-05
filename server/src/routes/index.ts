import express, { Router } from 'express';
import { analysisController } from '../controllers/analysisController.js';
import type { AppContext } from '../controllers/context.js';
import { feedbackController } from '../controllers/feedbackController.js';
import { intelController } from '../controllers/intelController.js';
import { samplesController } from '../controllers/samplesController.js';
import { systemController } from '../controllers/systemController.js';
import { analyzeLimiter } from '../middleware/security.js';
import { createUpload } from '../middleware/upload.js';

export function apiRouter(ctx: AppContext): Router {
  const router = Router();
  const analysis = analysisController(ctx);
  const system = systemController(ctx);
  const intel = intelController(ctx);
  const feedback = feedbackController(ctx);
  const samples = samplesController(ctx);
  const upload = createUpload(ctx.config.MAX_EMAIL_BYTES);
  // JSON payloads carry the email as a string; allow for escaping overhead.
  const json = express.json({ limit: Math.ceil(ctx.config.MAX_EMAIL_BYTES * 1.2) });

  router.post('/analyze', analyzeLimiter, upload.single('email'), analysis.analyzeUpload);
  router.post('/analyze/raw', analyzeLimiter, json, analysis.analyzeRaw);

  router.get('/analyses', analysis.list);
  router.get('/analyses/:id', analysis.get);
  router.get('/analyses/:id/raw', analysis.raw);
  router.get('/analyses/:id/report', analysis.report);
  router.delete('/analyses/:id', analysis.remove);

  router.post('/feedback', express.json({ limit: '16kb' }), feedback.submit);

  router.get('/stats', system.stats);
  router.get('/health', system.health);
  router.get('/model', system.model);
  router.get('/threat-intel/:domain', intel.lookup);

  router.get('/samples', samples.list);
  router.get('/samples/:label/:file', samples.get);
  return router;
}
