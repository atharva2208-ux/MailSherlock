import fs from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response } from 'express';
import { badRequest, notFound } from '../utils/errors.js';
import { sampleNameSchema } from '../validators/schemas.js';
import type { AppContext } from './context.js';

export function samplesController(ctx: AppContext) {
  const root = path.resolve(ctx.config.samplesDir);
  return {
    async list(_req: Request, res: Response) {
      const groups = await Promise.all(
        (['phishing', 'legitimate'] as const).map(async (label) => {
          const files = await fs.readdir(path.join(root, label)).catch(() => [] as string[]);
          return files
            .filter((f) => f.endsWith('.eml'))
            .sort()
            .map((file) => ({
              name: `${label}/${file}`,
              label,
              title: file.replace(/\.eml$/, '').replace(/-/g, ' '),
            }));
        }),
      );
      res.json({ success: true, samples: groups.flat() });
    },

    async get(req: Request, res: Response) {
      const name = sampleNameSchema.parse(`${req.params.label}/${req.params.file}`);
      const resolved = path.resolve(root, name);
      // Defence in depth: the schema already forbids traversal, but never trust one layer.
      if (!resolved.startsWith(root + path.sep))
        throw badRequest('invalid_path', 'Invalid sample path');
      const raw = await fs.readFile(resolved, 'utf8').catch(() => null);
      if (raw === null) throw notFound('Sample not found');
      res.type('text/plain; charset=utf-8').send(raw);
    },
  };
}
