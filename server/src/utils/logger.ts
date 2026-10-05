import pino from 'pino';

/**
 * Structured logger. Email content, addresses and secrets are never logged:
 * events carry identifiers, counts and timings only. The redact list is a
 * second line of defence in case an object is logged wholesale by mistake.
 */
export function createLogger(level: string) {
  return pino({
    level,
    base: { service: 'mailsherlock-api' },
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        '*.apiKey',
        '*.raw',
        '*.body',
        '*.text',
        'email',
        'raw',
      ],
      censor: '[redacted]',
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}

export type Logger = ReturnType<typeof createLogger>;
