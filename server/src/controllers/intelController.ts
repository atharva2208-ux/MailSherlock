import net from 'node:net';
import type { Request, Response } from 'express';
import { indicatorSchema } from '../validators/schemas.js';
import type { AppContext } from './context.js';

export function intelController(ctx: AppContext) {
  return {
    async lookup(req: Request, res: Response) {
      const indicator = indicatorSchema.parse(req.params.domain);
      const kind = net.isIPv4(indicator) ? 'ip' : 'domain';
      const [external] = await Promise.all([ctx.threatIntel.lookup(kind, indicator)]);
      res.json({
        success: true,
        indicator,
        kind,
        local: kind === 'domain' ? ctx.threatIntel.localDomainIntel(indicator) : null,
        external,
      });
    },
  };
}
