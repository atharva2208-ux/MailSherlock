export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const badRequest = (code: string, message: string, details?: unknown) =>
  new AppError(400, code, message, details);
export const notFound = (message = 'Resource not found') => new AppError(404, 'not_found', message);
export const payloadTooLarge = (limit: number) =>
  new AppError(
    413,
    'payload_too_large',
    `Email exceeds the ${Math.round(limit / 1024 / 1024)} MiB limit`,
  );
export const unprocessable = (code: string, message: string) => new AppError(422, code, message);
