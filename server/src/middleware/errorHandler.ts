import type { ErrorRequestHandler, RequestHandler } from 'express';
import multer from 'multer';
import { ZodError } from 'zod';
import type { ApiErrorBody } from '../models/analysis.js';
import { AppError } from '../utils/errors.js';
import type { Logger } from '../utils/logger.js';

export function toApiError(
  error: unknown,
  maxBytes: number,
): { status: number; body: ApiErrorBody } {
  if (error instanceof AppError)
    return {
      status: error.status,
      body: { code: error.code, message: error.message, details: error.details },
    };
  if (error instanceof ZodError) {
    return {
      status: 400,
      body: {
        code: 'validation_failed',
        message: 'The request is invalid.',
        details: error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      },
    };
  }
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return {
        status: 413,
        body: {
          code: 'payload_too_large',
          message: `Email exceeds the ${Math.round(maxBytes / 1048576)} MiB limit.`,
        },
      };
    }
    return {
      status: 400,
      body: {
        code: 'upload_rejected',
        message: `Upload rejected (${error.code.toLowerCase().replace(/_/g, ' ')}).`,
      },
    };
  }
  const typed = error as { type?: string; status?: number };
  if (typed?.type === 'entity.too.large')
    return {
      status: 413,
      body: {
        code: 'payload_too_large',
        message: `Email exceeds the ${Math.round(maxBytes / 1048576)} MiB limit.`,
      },
    };
  if (typed?.type === 'entity.parse.failed')
    return {
      status: 400,
      body: { code: 'invalid_json', message: 'Request body is not valid JSON.' },
    };
  return {
    status: 500,
    body: {
      code: 'internal_error',
      message: 'An unexpected error occurred. No data was modified.',
    },
  };
}

export function errorHandler(logger: Logger, maxBytes: number): ErrorRequestHandler {
  return (error, req, res, _next) => {
    const { status, body } = toApiError(error, maxBytes);
    if (status >= 500)
      logger.error(
        {
          event: 'error',
          path: req.path,
          err:
            error instanceof Error
              ? { name: error.name, message: error.message, stack: error.stack }
              : String(error),
        },
        'request failed',
      );
    else
      logger.warn(
        { event: 'request.rejected', path: req.path, status, code: body.code },
        'request rejected',
      );
    if (res.headersSent) {
      res.end();
      return;
    }
    res.status(status).json({ success: false, error: body });
  };
}

export const notFoundHandler: RequestHandler = (_req, res) => {
  res
    .status(404)
    .json({ success: false, error: { code: 'not_found', message: 'Endpoint not found.' } });
};

export function requestLogger(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = performance.now();
    res.on('finish', () => {
      logger.info(
        {
          event: 'http',
          method: req.method,
          path: req.path,
          status: res.statusCode,
          ms: Math.round(performance.now() - started),
        },
        'request',
      );
    });
    next();
  };
}
