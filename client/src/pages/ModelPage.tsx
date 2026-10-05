import { useQuery } from '@tanstack/react-query';
import { BrainCircuit } from 'lucide-react';
import { Field, Panel } from '../components/common/Panel';
import { EmptyState, ErrorState, Skeleton } from '../components/common/States';
import { api } from '../services/api';
import type { ModelMetrics } from '../types';
import { cx, formatDateTime, pct } from '../utils/format';
import { PageHeader } from './PageHeader';

function ConfusionMatrix({ cm }: { cm: ModelMetrics['confusion_matrix'] }) {
  const cell = (value: number, label: string, good: boolean) => (
    <div
      className={cx(
        'rounded-md border px-3 py-3',
        good
          ? 'border-line bg-raised'
          : 'border-[color-mix(in_srgb,var(--critical)_35%,transparent)] bg-[color-mix(in_srgb,var(--critical)_7%,transparent)]',
      )}
    >
      <p className="text-[22px] font-semibold tabular-nums">{value}</p>
      <p className="text-[12px] text-muted">{label}</p>
    </div>
  );
  return (
    <div className="grid grid-cols-[auto_1fr_1fr] gap-2 text-[12px]">
      <span />
      <span className="text-center text-muted">Predicted phishing</span>
      <span className="text-center text-muted">Predicted legitimate</span>
      <span className="self-center pr-2 text-right text-muted">Actual phishing</span>
      {cell(cm.tp, 'true positives', true)}
      {cell(cm.fn, 'missed phishing', false)}
      <span className="self-center pr-2 text-right text-muted">Actual legitimate</span>
      {cell(cm.fp, 'false positives', false)}
      {cell(cm.tn, 'true negatives', true)}
    </div>
  );
}

export default function ModelPage() {
  const { data, error, isLoading } = useQuery({ queryKey: ['model'], queryFn: api.model });
  if (isLoading) return <Skeleton className="h-96" />;
  if (error)
    return <ErrorState title="Model information unavailable" message={(error as Error).message} />;
  if (!data?.available || !data.metadata || !data.metrics) {
    return (
      <div className="rounded-lg border border-line bg-surface">
        <EmptyState icon={<BrainCircuit size={24} />} title="No trained model">
          {data?.message ?? 'Run the ML pipeline to train a model.'} Analyses still run with the
          rule-based engine.
        </EmptyState>
      </div>
    );
  }
  const meta = data.metadata;
  const { test, challenge, feature_weights: weights } = data.metrics;
  const testSamples = test.samples;

  const metrics: [string, number | null, string][] = [
    ['Precision', test.precision, 'of flagged emails were phishing'],
    ['Recall', test.recall, 'of phishing emails were caught'],
    ['F1', test.f1, 'harmonic mean of the two'],
    ['False positive rate', test.false_positive_rate, 'of legitimate emails flagged'],
    ['False negative rate', test.false_negative_rate, 'of phishing missed'],
    ['ROC-AUC', test.roc_auc, 'threshold-independent ranking'],
    ['PR-AUC', test.pr_auc, 'precision-recall area'],
    ['Accuracy', test.accuracy, 'reported, not optimised for'],
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title={meta.model_name}
        description={`Version ${meta.model_version} · ${meta.description}. Every figure on this page is read from the evaluation artifacts produced by the training pipeline.`}
        actions={
          <span className={cx('text-[12.5px]', data.serviceUp ? 'text-safe' : 'text-medium')}>
            {data.serviceUp
              ? 'Inference service online'
              : 'Inference service offline · showing saved artifacts'}
          </span>
        }
      />

      <Panel
        title="Held-out test set"
        description={`${testSamples.toLocaleString()} emails (${test.phishing} phishing, ${test.legitimate} legitimate) never seen in training or threshold selection, at threshold ${test.threshold}`}
      >
        <div className="grid grid-cols-2 gap-x-6 gap-y-4 md:grid-cols-4">
          {metrics.map(([label, value, hint]) => (
            <div key={label}>
              <p className="text-[12.5px] text-muted">{label}</p>
              <p className="text-[24px] leading-tight font-semibold tabular-nums">
                {label.includes('AUC') ? (value ?? 0).toFixed(4) : pct(value, 2)}
              </p>
              <p className="text-[11.5px] text-faint">{hint}</p>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Confusion matrix" description="Test split at the tuned threshold">
          <ConfusionMatrix cm={test.confusion_matrix} />
          <p className="mt-3 text-[12.5px] text-muted">
            At the default 0.5 threshold the same model would have{' '}
            {test.at_threshold_0_5.confusion_matrix.fp} false positives and{' '}
            {test.at_threshold_0_5.confusion_matrix.fn} misses.
          </p>
        </Panel>
        <Panel title="Training run">
          <dl>
            <Field label="Trained">{formatDateTime(meta.training_date)}</Field>
            <Field label="Dataset version" mono>
              {meta.dataset_version}
            </Field>
            <Field label="Feature version" mono>
              {meta.feature_version}
            </Field>
            <Field label="Training samples">{`${meta.training_samples.toLocaleString()} (${meta.training_phishing} phishing, ${meta.training_legitimate} legitimate)`}</Field>
            <Field label="Validation samples">{meta.validation_samples.toLocaleString()}</Field>
            <Field label="Test samples">{testSamples.toLocaleString()}</Field>
            <Field label="Threshold">{`${meta.threshold.toFixed(4)} - ${meta.threshold_policy}`}</Field>
            <Field label="Environment">
              {Object.entries(meta.environment)
                .map(([k, v]) => `${k} ${v}`)
                .join(', ')}
            </Field>
          </dl>
        </Panel>
      </div>

      <Panel title="Model selection" description={meta.selection.criterion} bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-[13px]">
            <thead className="text-[12px] whitespace-nowrap text-muted">
              <tr className="border-b border-line">
                <th className="px-4 py-2 font-medium">Candidate</th>
                <th className="px-3 py-2 font-medium">Recall @ FPR ≤ 1%</th>
                <th className="px-3 py-2 font-medium">PR-AUC</th>
                <th className="px-3 py-2 font-medium">Train time</th>
                <th className="px-3 py-2 font-medium">Production eligibility</th>
              </tr>
            </thead>
            <tbody>
              {meta.selection.candidates.map((c) => (
                <tr
                  key={c.candidate}
                  className={cx(
                    'border-b border-line last:border-b-0',
                    c.candidate === meta.candidate && 'bg-accent-soft',
                  )}
                >
                  <td className="px-4 py-2">
                    <span className="font-medium">{c.candidate}</span>
                    {c.candidate === meta.candidate && (
                      <span className="ml-2 text-[12px] text-accent">selected</span>
                    )}
                    <span className="block text-[12px] text-muted">{c.description}</span>
                  </td>
                  <td className="px-3 py-2 tabular-nums">{pct(c.recall_at_target_fpr, 2)}</td>
                  <td className="px-3 py-2 tabular-nums">{c.validation.pr_auc?.toFixed(4)}</td>
                  <td className="px-3 py-2 tabular-nums text-muted">{c.train_seconds}s</td>
                  <td className="px-3 py-2 text-[12.5px]">
                    {c.prior_violations?.length ? (
                      <span className="text-high">
                        Rejected: learned{' '}
                        {c.prior_violations
                          .map((v) => `${v.feature.replace(/_/g, ' ')} ⇒ legitimate`)
                          .join(', ')}
                      </span>
                    ) : c.eligible ? (
                      <span className="text-safe">Eligible</span>
                    ) : (
                      <span className="text-muted">Benchmark only (not exactly explainable)</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title="Modern challenge set"
        description={`${challenge.legitimate} legitimate and ${challenge.phishing} phishing hand-written modern emails, used for evaluation only`}
      >
        <p className="mb-3 max-w-[85ch] text-[13px]">
          The model alone flags{' '}
          <strong className="text-critical">
            {challenge.confusion_matrix.fp} of {challenge.legitimate}
          </strong>{' '}
          modern legitimate emails and misses{' '}
          <strong>
            {challenge.confusion_matrix.fn} of {challenge.phishing}
          </strong>{' '}
          phishing emails. Its legitimate training data is 2002-era mailing-list mail with no
          password resets, receipts or security alerts, so it treats any direct &ldquo;your
          account&rdquo; message as suspicious. This is why ML only corroborates rule evidence in
          MailSherlock and is damped for authenticated senders.
        </p>
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead className="sticky top-0 bg-surface text-muted">
              <tr className="border-b border-line">
                <th className="py-1.5 font-medium">Subject</th>
                <th className="w-28 py-1.5 font-medium">Label</th>
                <th className="w-28 py-1.5 font-medium">P(phishing)</th>
                <th className="w-28 py-1.5 font-medium">Model says</th>
              </tr>
            </thead>
            <tbody>
              {challenge.predictions.map((p) => (
                <tr key={p.id} className="border-b border-line last:border-b-0">
                  <td className="py-1.5">{p.subject}</td>
                  <td className="py-1.5 capitalize">{p.label}</td>
                  <td className="py-1.5 tabular-nums">{pct(p.probability, 1)}</td>
                  <td
                    className={cx(
                      'py-1.5 capitalize',
                      p.predicted !== p.label && 'font-medium text-critical',
                    )}
                  >
                    {p.predicted}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        {weights && (
          <Panel
            title="Strongest global weights"
            description="Audited for dataset artefacts after every training run"
          >
            <div className="grid grid-cols-2 gap-4 text-[12.5px]">
              {(['phishing', 'legitimate'] as const).map((side) => (
                <div key={side}>
                  <p
                    className="mb-1.5 font-medium"
                    style={{ color: side === 'phishing' ? 'var(--critical)' : 'var(--safe)' }}
                  >
                    Toward {side}
                  </p>
                  <ul className="space-y-0.5">
                    {weights[side].slice(0, 12).map((w, i) => (
                      <li key={i} className="flex justify-between gap-2">
                        <code className="truncate font-mono">{w.feature}</code>
                        <span className="tabular-nums text-muted">{w.weight.toFixed(2)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </Panel>
        )}
        <Panel title="Training data">
          <ul className="space-y-3 text-[13px]">
            {meta.dataset_sources.map((s) => (
              <li key={s.name}>
                <p className="font-medium">
                  {s.name}{' '}
                  <span className="text-[12px] font-normal text-muted">
                    · {s.label} · {s.license}
                  </span>
                </p>
                <p className="text-muted">{s.description}</p>
                <p className="font-mono text-[11.5px] break-all text-faint">{s.url}</p>
              </li>
            ))}
          </ul>
          <p className="mt-3 border-t border-line pt-3 text-[12.5px] text-muted">
            Messages are de-duplicated, restricted to English, and split by near-duplicate campaign
            group so templates never appear in both training and test data. Corpora are downloaded
            by script and never committed.
          </p>
        </Panel>
      </div>
    </div>
  );
}
