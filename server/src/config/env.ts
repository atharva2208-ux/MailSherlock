import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const REPO_ROOT = path.resolve(serverRoot, '..');

dotenv.config({ path: path.join(REPO_ROOT, '.env'), quiet: true });
dotenv.config({ path: path.join(serverRoot, '.env'), quiet: true });

const boolean = z
  .enum(['true', 'false', '1', '0', ''])
  .optional()
  .transform((value) => value === 'true' || value === '1');
const optionalSecret = z
  .string()
  .optional()
  .transform((value) => (value && value.trim() ? value.trim() : undefined));

const schema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  DATABASE_PATH: z.string().default('./var/mailsherlock.sqlite'),
  MAX_EMAIL_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .max(50 * 1024 * 1024)
    .default(10 * 1024 * 1024),
  STORE_RAW_SOURCE: z
    .enum(['true', 'false'])
    .default('true')
    .transform((value) => value === 'true'),
  ML_SERVICE_URL: z.url().default('http://127.0.0.1:8001'),
  ML_TIMEOUT_MS: z.coerce.number().int().min(100).max(60000).default(4000),
  VIRUSTOTAL_API_KEY: optionalSecret,
  ABUSEIPDB_API_KEY: optionalSecret,
  URLSCAN_API_KEY: optionalSecret,
  GOOGLE_SAFE_BROWSING_API_KEY: optionalSecret,
  RDAP_ENABLED: boolean,
  ENRICH_ON_ANALYZE: boolean,
  THREAT_INTEL_TIMEOUT_MS: z.coerce.number().int().min(500).max(30000).default(5000),
});

export type AppConfig = z.infer<typeof schema> & {
  databaseFile: string;
  modelArtifactsDir: string;
  samplesDir: string;
  clientDistDir: string;
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration - ${problems}`);
  }
  const config = parsed.data;
  return {
    ...config,
    databaseFile:
      config.DATABASE_PATH === ':memory:'
        ? ':memory:'
        : path.resolve(serverRoot, config.DATABASE_PATH),
    modelArtifactsDir: path.join(REPO_ROOT, 'ml', 'artifacts', 'models'),
    samplesDir: path.join(REPO_ROOT, 'samples'),
    clientDistDir: path.join(REPO_ROOT, 'client', 'dist'),
  };
}

export const ENGINE_VERSION = '1.0.0';
