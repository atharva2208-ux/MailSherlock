import type { Generated } from 'kysely';

/**
 * Relational schema. Summary columns are denormalised from the full result
 * JSON so the history table, filters and dashboard query indexed columns
 * instead of parsing JSON. Types are written for portability to PostgreSQL.
 */
export interface AnalysesTable {
  id: string;
  created_at: string;
  source_name: string;
  sender_address: string;
  sender_domain: string;
  subject: string;
  risk_score: number;
  risk_level: string;
  classification: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  ml_probability: number | null;
  model_version: string | null;
  message_sha256: string;
  size_bytes: number;
  engine_version: string;
  result_json: string;
  raw_source: string | null;
}

export interface FindingsTable {
  id: Generated<number>;
  analysis_id: string;
  detector: string;
  category: string;
  severity: string;
  title: string;
  created_at: string;
}

export interface FeedbackTable {
  id: Generated<number>;
  analysis_id: string;
  verdict: string;
  notes: string | null;
  created_at: string;
  /** Feedback becomes training data only after a reviewer sets this. */
  reviewed: number;
}

export interface Database {
  analyses: AnalysesTable;
  findings: FindingsTable;
  feedback: FeedbackTable;
}
