import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import type { AppContext } from './controllers/context.js';
import { errorHandler, notFoundHandler, requestLogger } from './middleware/errorHandler.js';
import { apiLimiter, securityHeaders } from './middleware/security.js';
import { apiRouter } from './routes/index.js';

export function createApp(ctx: AppContext) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback');
  app.use(securityHeaders);
  app.use(requestLogger(ctx.logger));

  if (ctx.config.NODE_ENV !== 'production') {
    // The Vite dev server proxies /api, but allow direct calls from it as well.
    app.use('/api', (req, res, next) => {
      const origin = req.headers.origin;
      if (origin && origin === ctx.config.CORS_ORIGIN) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Headers', 'content-type, accept');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE');
        if (req.method === 'OPTIONS') {
          res.status(204).end();
          return;
        }
      }
      next();
    });
  }

  app.use('/api', apiLimiter, apiRouter(ctx));
  app.use('/api', notFoundHandler);

  if (fs.existsSync(path.join(ctx.config.clientDistDir, 'index.html'))) {
    app.use(express.static(ctx.config.clientDistDir, { index: false, maxAge: '1h' }));
    app.get(/^(?!\/api\/).*/, (_req, res) =>
      res.sendFile(path.join(ctx.config.clientDistDir, 'index.html')),
    );
  }

  app.use(errorHandler(ctx.logger, ctx.config.MAX_EMAIL_BYTES));
  return app;
}
