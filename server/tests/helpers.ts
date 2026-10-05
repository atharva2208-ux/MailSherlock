import fs from 'node:fs';
import path from 'node:path';
import { loadConfig, REPO_ROOT } from '../src/config/env.js';
import { createContext } from '../src/bootstrap.js';
import type { MlAssessment } from '../src/models/analysis.js';
import type { MlClient } from '../src/services/enrichment/mlClient.js';

export function sample(name: string): Buffer {
  return fs.readFileSync(path.join(REPO_ROOT, 'samples', name));
}

export function fixture(name: string): Buffer {
  return fs.readFileSync(path.join(import.meta.dirname, 'fixtures', name));
}

/** ML client stub: lets tests control the classifier output deterministically. */
export function fakeMl(assessment: MlAssessment | null = null): MlClient {
  return {
    predict: async () => assessment ?? { available: false, reason: 'ML service is not reachable' },
    health: async () =>
      assessment
        ? { up: true, detail: 'Model v1.0.0 loaded', latencyMs: 1 }
        : { up: false, detail: 'Inference service not reachable' },
    modelInfo: async () => null,
  };
}

export async function testContext(ml: MlClient = fakeMl(), env: Record<string, string> = {}) {
  const config = loadConfig({
    ...process.env,
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    DATABASE_PATH: ':memory:',
    ...env,
  });
  return createContext(config, { ml });
}

/** Minimal STORED (uncompressed) ZIP containing the given file names. */
export function buildZip(names: string[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const name of names) {
    const nameBuf = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf);
    centrals.push(central, nameBuf);
    offset += local.length + nameBuf.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}
