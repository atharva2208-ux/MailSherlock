import fs from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response } from 'express';
import { ENGINE_VERSION } from '../config/env.js';
import { pingDatabase } from '../db/database.js';
import type { ComponentHealth, HealthReport } from '../models/analysis.js';
import type { AppContext } from './context.js';

const ML_HEALTH_TTL_MS = 5000;

async function readModelArtifacts(dir: string) {
  try {
    const version = (await fs.readFile(path.join(dir, 'LATEST'), 'utf8')).trim();
    const versionDir = path.join(dir, `v${version}`);
    const [metadata, metrics] = await Promise.all([
      fs.readFile(path.join(versionDir, 'metadata.json'), 'utf8').then(JSON.parse),
      fs.readFile(path.join(versionDir, 'metrics.json'), 'utf8').then(JSON.parse),
    ]);
    return { metadata, metrics };
  } catch {
    return null;
  }
}

export function systemController(ctx: AppContext) {
  let mlHealthCache: { at: number; value: ComponentHealth } | null = null;

  const mlHealth = async (): Promise<ComponentHealth> => {
    if (mlHealthCache && Date.now() - mlHealthCache.at < ML_HEALTH_TTL_MS)
      return mlHealthCache.value;
    const result = await ctx.ml.health();
    const value: ComponentHealth = {
      status: result.up ? 'up' : 'down',
      detail: result.up
        ? result.detail
        : `${result.detail} - analyses use rule-based detection only`,
      latencyMs: result.latencyMs,
    };
    mlHealthCache = { at: Date.now(), value };
    return value;
  };

  return {
    async health(_req: Request, res: Response) {
      let database: ComponentHealth;
      try {
        database = {
          status: 'up',
          detail: 'SQLite responding',
          latencyMs: await pingDatabase(ctx.db),
        };
      } catch (error) {
        database = {
          status: 'down',
          detail: error instanceof Error ? error.message : 'unreachable',
        };
      }

      let storage: ComponentHealth;
      if (ctx.config.databaseFile === ':memory:')
        storage = { status: 'up', detail: 'In-memory database (test mode)' };
      else {
        try {
          await fs.access(path.dirname(ctx.config.databaseFile), fs.constants.W_OK);
          const stat = await fs.stat(ctx.config.databaseFile).catch(() => null);
          storage = {
            status: 'up',
            detail: `Writable · ${stat ? (stat.size / 1048576).toFixed(2) : '0.00'} MiB used`,
          };
        } catch {
          storage = { status: 'down', detail: 'Database directory is not writable' };
        }
      }

      const threatIntel: Record<string, ComponentHealth> = {};
      for (const provider of ctx.threatIntel.providers) {
        threatIntel[provider.name] = provider.configured
          ? {
              status: 'up',
              detail: ctx.config.ENRICH_ON_ANALYZE
                ? 'Configured · automatic enrichment on'
                : 'Configured · on-demand lookups',
            }
          : { status: 'not_configured', detail: 'Not configured' };
      }

      const ml = await mlHealth();
      const report: HealthReport = {
        status: database.status === 'up' && ml.status === 'up' ? 'ok' : 'degraded',
        version: ENGINE_VERSION,
        uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
        components: {
          api: { status: 'up', detail: 'Analysis engine online' },
          database,
          ml,
          storage,
          threatIntel,
        },
      };
      res.status(database.status === 'up' ? 200 : 503).json({ success: true, ...report });
    },

    async model(_req: Request, res: Response) {
      const live = (await ctx.ml.modelInfo()) as { metadata: unknown; metrics: unknown } | null;
      if (live) {
        res.json({ success: true, available: true, source: 'service', serviceUp: true, ...live });
        return;
      }
      const artifacts = await readModelArtifacts(ctx.config.modelArtifactsDir);
      if (artifacts) {
        res.json({
          success: true,
          available: true,
          source: 'artifacts',
          serviceUp: false,
          ...artifacts,
        });
        return;
      }
      res.json({
        success: true,
        available: false,
        serviceUp: false,
        message: 'No trained model found. Run the ML pipeline (see docs/ml-pipeline.md).',
      });
    },

    async stats(_req: Request, res: Response) {
      res.json({ success: true, ...(await ctx.analyses.stats()) });
    },
  };
}
