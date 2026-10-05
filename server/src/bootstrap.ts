import type { AppConfig } from './config/env.js';
import type { AppContext } from './controllers/context.js';
import { createDatabase, migrate } from './db/database.js';
import { AnalysisRepository } from './repositories/analysisRepository.js';
import { FeedbackRepository } from './repositories/feedbackRepository.js';
import { createMlClient, type MlClient } from './services/enrichment/mlClient.js';
import { ThreatIntelService } from './services/enrichment/threatIntel.js';
import { createLogger } from './utils/logger.js';

export async function createContext(
  config: AppConfig,
  overrides: { ml?: MlClient } = {},
): Promise<AppContext> {
  const logger = createLogger(config.LOG_LEVEL);
  const db = createDatabase(config.databaseFile);
  await migrate(db);
  return {
    config,
    logger,
    db,
    analyses: new AnalysisRepository(db),
    feedback: new FeedbackRepository(db),
    ml: overrides.ml ?? createMlClient(config.ML_SERVICE_URL, config.ML_TIMEOUT_MS),
    threatIntel: new ThreatIntelService(config, logger),
    startedAt: Date.now(),
  };
}
