import type { AppConfig } from '../config/env.js';
import type { Db } from '../db/database.js';
import type { AnalysisRepository } from '../repositories/analysisRepository.js';
import type { FeedbackRepository } from '../repositories/feedbackRepository.js';
import type { MlClient } from '../services/enrichment/mlClient.js';
import type { ThreatIntelService } from '../services/enrichment/threatIntel.js';
import type { Logger } from '../utils/logger.js';

/** Dependencies shared by controllers; injected so tests can substitute fakes. */
export interface AppContext {
  config: AppConfig;
  logger: Logger;
  db: Db;
  analyses: AnalysisRepository;
  feedback: FeedbackRepository;
  ml: MlClient;
  threatIntel: ThreatIntelService;
  startedAt: number;
}
