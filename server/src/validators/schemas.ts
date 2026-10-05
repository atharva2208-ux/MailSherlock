import { z } from 'zod';

export const RISK_LEVELS = ['critical', 'high', 'medium', 'low', 'safe'] as const;
export const CLASSIFICATIONS = ['phishing', 'suspicious', 'legitimate'] as const;
export const FEEDBACK_VERDICTS = [
  'confirmed_phishing',
  'confirmed_legitimate',
  'false_positive',
  'false_negative',
  'uncertain',
] as const;
export const SORT_FIELDS = [
  'created_at',
  'risk_score',
  'finding_count',
  'sender_address',
  'subject',
  'classification',
] as const;

const csvList = <T extends readonly [string, ...string[]]>(values: T) =>
  z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((value) =>
      value === undefined
        ? []
        : (Array.isArray(value) ? value : value.split(',')).map((v) => v.trim()).filter(Boolean),
    )
    .pipe(z.array(z.enum(values)));

export const analysisIdSchema = z.string().regex(/^an_[a-z0-9]{10,40}$/, 'Invalid analysis id');

export const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  search: z.string().trim().max(200).optional(),
  riskLevel: csvList(RISK_LEVELS),
  classification: csvList(CLASSIFICATIONS),
  from: z.iso.datetime({ offset: true }).or(z.iso.date()).optional(),
  to: z.iso.datetime({ offset: true }).or(z.iso.date()).optional(),
  sort: z.enum(SORT_FIELDS).default('created_at'),
  order: z.enum(['asc', 'desc']).default('desc'),
});
export type ListQuery = z.infer<typeof listQuerySchema>;

export const rawAnalyzeSchema = z.object({
  raw: z.string().min(1, 'Email content is required'),
  sourceName: z.string().trim().max(200).optional(),
});

export const feedbackSchema = z.object({
  analysisId: analysisIdSchema,
  verdict: z.enum(FEEDBACK_VERDICTS),
  notes: z.string().trim().max(2000).optional(),
});

// RFC 1035 hostname (with optional IDN punycode) or an IPv4 address.
export const indicatorSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(253)
  .refine(
    (value) =>
      /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(
        value,
      ) || /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value),
    'Expected a domain name or IPv4 address',
  );

export const sampleNameSchema = z
  .string()
  .regex(/^(phishing|legitimate)\/[a-z0-9-]{1,80}\.eml$/, 'Unknown sample');
