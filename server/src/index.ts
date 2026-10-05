import { createApp } from './app.js';
import { createContext } from './bootstrap.js';
import { loadConfig } from './config/env.js';

const config = loadConfig();
const ctx = await createContext(config);
const app = createApp(ctx);

const server = app.listen(config.PORT, () => {
  ctx.logger.info(
    { event: 'server.started', port: config.PORT, env: config.NODE_ENV },
    `MailSherlock API listening on http://localhost:${config.PORT}`,
  );
});

const shutdown = (signal: string) => {
  ctx.logger.info({ event: 'server.stopping', signal }, 'shutting down');
  server.close(() => {
    void ctx.db.destroy().finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
