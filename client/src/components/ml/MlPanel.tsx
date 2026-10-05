import { BrainCircuit } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { MlAssessment } from '../../types';
import { pct } from '../../utils/format';
import { Panel } from '../common/Panel';

const KIND = { term: 'Term', structural: 'Structure', character_patterns: 'Characters' } as const;
// The model sees masked placeholders instead of raw links, addresses and numbers.
const TOKEN_LABEL: Record<string, string> = {
  urltoken: '[link]',
  emailtoken: '[email address]',
  '0': '[number]',
};
const displayTerm = (term: string) =>
  term
    .split(' ')
    .map((t) => TOKEN_LABEL[t] ?? t)
    .join(' ');

/** What the classifier said and which features drove it - exact linear contributions, not post-hoc guesses. */
export function MlPanel({ ml, mlPoints }: { ml: MlAssessment; mlPoints?: number }) {
  if (!ml.available) {
    return (
      <Panel>
        <div className="flex gap-3">
          <BrainCircuit size={20} className="shrink-0 text-faint" />
          <div className="text-[13px]">
            <p className="font-semibold">Machine learning enrichment unavailable.</p>
            <p className="mt-1 text-muted">
              Results are based on rule-based analysis. {ml.reason ? `Reason: ${ml.reason}.` : ''}
            </p>
            <p className="mt-1 text-muted">
              Start the inference service with <code className="font-mono">npm run ml:serve</code>.
            </p>
          </div>
        </div>
      </Panel>
    );
  }
  // Character n-grams are summed into one aggregate; plotting it on the same
  // scale as single terms would flatten every other bar, so it is reported apart.
  const characterAggregate = ml.signals?.find((s) => s.kind === 'character_patterns');
  const signals = (ml.signals ?? []).filter((s) => s.kind !== 'character_patterns');
  const max = Math.max(0.01, ...signals.map((s) => Math.abs(s.weight)));
  const probability = (ml.probability ?? 0) * 100;
  const threshold = (ml.threshold ?? 0.5) * 100;

  return (
    <div className="grid gap-4 lg:grid-cols-[340px_minmax(0,1fr)]">
      <Panel title="Classifier output">
        <p className="text-[13px] text-muted">Phishing probability</p>
        <p
          className="text-[40px] leading-tight font-semibold tabular-nums"
          style={{ color: ml.label === 'phishing' ? 'var(--critical)' : 'var(--safe)' }}
        >
          {pct(ml.probability, 0)}
        </p>
        <div
          className="relative mt-2 mb-9 h-2 rounded-full bg-raised"
          role="img"
          aria-label={`Probability ${probability.toFixed(0)}%, decision threshold ${threshold.toFixed(0)}%`}
        >
          <div
            className="h-full rounded-full"
            style={{
              width: `${probability}%`,
              background: ml.label === 'phishing' ? 'var(--critical)' : 'var(--safe)',
            }}
          />
          <span className="absolute -top-1 h-4 w-0.5 bg-text" style={{ left: `${threshold}%` }} />
          <span
            className="absolute top-4 -translate-x-1/2 text-[11px] text-muted"
            style={{ left: `${threshold}%` }}
          >
            threshold {threshold.toFixed(0)}%
          </span>
        </div>
        <dl className="space-y-1.5 text-[13px]">
          <div className="flex justify-between">
            <dt className="text-muted">Model</dt>
            <dd>
              <Link to="/model" className="hover:text-accent">
                {ml.modelName} v{ml.modelVersion}
              </Link>
            </dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-muted">Confidence</dt>
            <dd className="capitalize">{ml.confidence}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-muted">Vocabulary coverage</dt>
            <dd>{pct(ml.vocabularyCoverage, 0)}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-muted">Inference time</dt>
            <dd>{ml.inferenceMs} ms</dd>
          </div>
          {mlPoints !== undefined && (
            <div className="flex justify-between">
              <dt className="text-muted">Score contribution</dt>
              <dd>
                {mlPoints > 0 ? '+' : ''}
                {mlPoints}
              </dd>
            </div>
          )}
        </dl>
        <p className="mt-4 border-t border-line pt-3 text-[12px] text-muted">
          The model corroborates rule evidence; it cannot raise a verdict on its own. It was trained
          mostly on older legitimate mail and over-flags modern transactional email, so its weight
          is reduced for authenticated senders.
        </p>
      </Panel>
      <Panel
        title="Key signals"
        description="Exact per-feature contributions to the model's log-odds for this message"
      >
        {signals.length ? (
          <ul className="space-y-1.5">
            {signals.slice(0, 14).map((s, i) => (
              <li
                key={i}
                className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)_52px] items-center gap-3 text-[13px]"
              >
                <span className="truncate" title={s.feature}>
                  <span className="mr-1.5 text-[11.5px] text-faint">{KIND[s.kind]}</span>
                  {s.kind === 'term' ? (
                    <code className="font-mono text-[12.5px]">{displayTerm(s.feature)}</code>
                  ) : (
                    s.feature
                  )}
                </span>
                <span className="relative h-2 rounded bg-raised">
                  <span className="absolute inset-y-0 left-1/2 w-px bg-line-strong" />
                  <span
                    className="absolute inset-y-0 rounded"
                    style={{
                      background: s.weight > 0 ? 'var(--critical)' : 'var(--safe)',
                      width: `${(Math.abs(s.weight) / max) * 50}%`,
                      left: s.weight > 0 ? '50%' : `${50 - (Math.abs(s.weight) / max) * 50}%`,
                    }}
                  />
                </span>
                <span
                  className="text-right text-[12px] tabular-nums"
                  style={{ color: s.weight > 0 ? 'var(--critical)' : 'var(--safe)' }}
                >
                  {s.weight > 0 ? '+' : ''}
                  {s.weight.toFixed(2)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[13px] text-muted">
            No feature-level explanation available for this model.
          </p>
        )}
        {characterAggregate && (
          <p className="mt-4 text-[13px]">
            Character n-gram patterns, summed:{' '}
            <span
              className="font-medium tabular-nums"
              style={{ color: characterAggregate.weight > 0 ? 'var(--critical)' : 'var(--safe)' }}
            >
              {characterAggregate.weight > 0 ? '+' : ''}
              {characterAggregate.weight.toFixed(2)}
            </span>{' '}
            <span className="text-muted">
              - sub-word spelling patterns that make the model robust to obfuscated words.
            </span>
          </p>
        )}
        <p className="mt-3 text-[12px] text-muted">
          Red pushes toward phishing, green toward legitimate. Contributions describe what the model
          weighed, not proof of intent.
        </p>
      </Panel>
    </div>
  );
}
