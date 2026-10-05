/**
 * Run every sample email (and optionally the ML challenge set) through the
 * full pipeline and print the verdicts. Used to sanity-check detection
 * changes end-to-end: `npm run analyze-samples -w server`.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createContext } from '../src/bootstrap.js';
import { loadConfig, REPO_ROOT } from '../src/config/env.js';
import { analyzeEmail } from '../src/services/analysisPipeline.js';

const config = loadConfig({ ...process.env, DATABASE_PATH: ':memory:', LOG_LEVEL: 'silent' });
const ctx = await createContext(config);
const deps = {
  config,
  logger: ctx.logger,
  repository: ctx.analyses,
  ml: ctx.ml,
  threatIntel: ctx.threatIntel,
};

const rows: string[][] = [];
for (const label of ['phishing', 'legitimate']) {
  const dir = path.join(REPO_ROOT, 'samples', label);
  for (const file of fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.eml'))
    .sort()) {
    const result = await analyzeEmail(deps, {
      raw: fs.readFileSync(path.join(dir, file)),
      sourceName: file,
    });
    const ml = result.ml.available ? `${(result.ml.probability! * 100).toFixed(0)}%` : 'n/a';
    rows.push([
      label,
      file,
      String(result.risk.score),
      result.risk.level,
      result.risk.classification,
      ml,
      String(result.findings.length),
      result.risk.trustedContext ? 'trusted' : '',
    ]);
    if (process.argv.includes('--verbose')) {
      for (const f of result.findings)
        console.log(
          `   ${f.severity.padEnd(8)} ${f.title}${f.adjustment ? ` (adjusted from ${f.adjustment.from})` : ''}`,
        );
      for (const c of result.risk.contributions)
        console.log(`   ${String(c.points).padStart(6)}  ${c.label}`);
    }
  }
}
if (process.argv.includes('--challenge')) {
  // The challenge messages carry no authentication headers, so the trusted
  // sender context can never apply: this measures the engine without its
  // main false-positive control, i.e. a pessimistic bound.
  const lines = fs
    .readFileSync(path.join(REPO_ROOT, 'ml/datasets/challenge/challenge.jsonl'), 'utf8')
    .trim()
    .split('\n');
  const tally: Record<string, Record<string, number>> = { legitimate: {}, phishing: {} };
  for (const line of lines) {
    const record = JSON.parse(line) as {
      label: 'legitimate' | 'phishing';
      subject: string;
      body: string;
    };
    const raw = Buffer.from(
      `From: sender@example.com\nTo: analyst@example.org\nSubject: ${record.subject}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n${record.body}\n`,
    );
    const result = await analyzeEmail(deps, { raw, sourceName: 'challenge' });
    const bucket = tally[record.label]!;
    bucket[result.risk.classification] = (bucket[result.risk.classification] ?? 0) + 1;
    if (process.argv.includes('--verbose'))
      console.log(
        `${record.label.padEnd(11)} ${result.risk.classification.padEnd(11)} ${String(result.risk.score).padStart(3)}  ${record.subject}`,
      );
  }
  console.log('challenge set (hybrid engine):', JSON.stringify(tally));
}
console.log(
  ['expected', 'sample', 'score', 'level', 'classification', 'ml', 'findings', 'context'].join(
    '\t',
  ),
);
for (const row of rows) console.log(row.join('\t'));
await ctx.db.destroy();
