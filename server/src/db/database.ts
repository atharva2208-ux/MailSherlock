import fs from 'node:fs';
import path from 'node:path';
import SQLite from 'better-sqlite3';
import { Kysely, SqliteDialect, sql } from 'kysely';
import type { Database } from './schema.js';

export type Db = Kysely<Database>;

export function createDatabase(file: string): Db {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const sqlite = new SQLite(file);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  sqlite.pragma('busy_timeout = 5000');
  return new Kysely<Database>({ dialect: new SqliteDialect({ database: sqlite }) });
}

/** Idempotent schema creation. Uses Kysely's builder so it ports to PostgreSQL. */
export async function migrate(db: Db): Promise<void> {
  await db.schema
    .createTable('analyses')
    .ifNotExists()
    .addColumn('id', 'text', (c) => c.primaryKey())
    .addColumn('created_at', 'text', (c) => c.notNull())
    .addColumn('source_name', 'text', (c) => c.notNull())
    .addColumn('sender_address', 'text', (c) => c.notNull())
    .addColumn('sender_domain', 'text', (c) => c.notNull())
    .addColumn('subject', 'text', (c) => c.notNull())
    .addColumn('risk_score', 'integer', (c) => c.notNull())
    .addColumn('risk_level', 'text', (c) => c.notNull())
    .addColumn('classification', 'text', (c) => c.notNull())
    .addColumn('finding_count', 'integer', (c) => c.notNull())
    .addColumn('critical_count', 'integer', (c) => c.notNull())
    .addColumn('high_count', 'integer', (c) => c.notNull())
    .addColumn('ml_probability', 'real')
    .addColumn('model_version', 'text')
    .addColumn('message_sha256', 'text', (c) => c.notNull())
    .addColumn('size_bytes', 'integer', (c) => c.notNull())
    .addColumn('engine_version', 'text', (c) => c.notNull())
    .addColumn('result_json', 'text', (c) => c.notNull())
    .addColumn('raw_source', 'text')
    .execute();

  await db.schema
    .createTable('findings')
    .ifNotExists()
    .addColumn('id', 'integer', (c) => c.primaryKey().autoIncrement())
    .addColumn('analysis_id', 'text', (c) =>
      c.notNull().references('analyses.id').onDelete('cascade'),
    )
    .addColumn('detector', 'text', (c) => c.notNull())
    .addColumn('category', 'text', (c) => c.notNull())
    .addColumn('severity', 'text', (c) => c.notNull())
    .addColumn('title', 'text', (c) => c.notNull())
    .addColumn('created_at', 'text', (c) => c.notNull())
    .execute();

  await db.schema
    .createTable('feedback')
    .ifNotExists()
    .addColumn('id', 'integer', (c) => c.primaryKey().autoIncrement())
    .addColumn('analysis_id', 'text', (c) =>
      c.notNull().references('analyses.id').onDelete('cascade'),
    )
    .addColumn('verdict', 'text', (c) => c.notNull())
    .addColumn('notes', 'text')
    .addColumn('created_at', 'text', (c) => c.notNull())
    .addColumn('reviewed', 'integer', (c) => c.notNull().defaultTo(0))
    .execute();

  const indexes: [string, 'analyses' | 'findings' | 'feedback', string[]][] = [
    ['idx_analyses_created', 'analyses', ['created_at']],
    ['idx_analyses_level', 'analyses', ['risk_level']],
    ['idx_analyses_class', 'analyses', ['classification']],
    ['idx_analyses_sha', 'analyses', ['message_sha256']],
    ['idx_findings_analysis', 'findings', ['analysis_id']],
    ['idx_findings_category', 'findings', ['category']],
    ['idx_feedback_analysis', 'feedback', ['analysis_id']],
  ];
  for (const [name, table, columns] of indexes) {
    await db.schema.createIndex(name).ifNotExists().on(table).columns(columns).execute();
  }
}

export async function pingDatabase(db: Db): Promise<number> {
  const started = performance.now();
  await sql`select 1`.execute(db);
  return Math.round((performance.now() - started) * 100) / 100;
}
