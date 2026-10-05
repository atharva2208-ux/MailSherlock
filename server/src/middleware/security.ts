import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      // Inline styles are needed for chart rendering; inline scripts are not allowed.
      'style-src': ["'self'", "'unsafe-inline'"],
      // Email images are stripped server-side; only local assets may load.
      'img-src': ["'self'", 'data:'],
      'connect-src': ["'self'"],
      'frame-src': ["'self'"],
      'frame-ancestors': ["'none'"],
      'form-action': ["'self'"],
      'object-src': ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' },
});

export const analyzeLimiter = rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'rate_limited',
      message: 'Too many analyses in a short period. Try again in a minute.',
    },
  },
});

export const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: 600,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    error: { code: 'rate_limited', message: 'Too many requests. Try again shortly.' },
  },
});
