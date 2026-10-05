import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { FEEDBACK_LABEL } from '../../constants/severity';
import { api } from '../../services/api';
import type { AnalysisResult, FeedbackVerdict } from '../../types';
import { cx, formatDateTime } from '../../utils/format';
import { Button } from '../common/Button';
import { useToast } from '../common/Toast';

const VERDICTS = Object.keys(FEEDBACK_LABEL) as FeedbackVerdict[];

export function FeedbackControl({ analysis }: { analysis: AnalysisResult }) {
  const [verdict, setVerdict] = useState<FeedbackVerdict | null>(
    analysis.feedback?.verdict ?? null,
  );
  const [notes, setNotes] = useState('');
  const { notify } = useToast();
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => api.submitFeedback(analysis.id, verdict!, notes),
    onSuccess: (feedback) => {
      notify('success', 'Feedback recorded', FEEDBACK_LABEL[feedback.verdict]);
      setNotes('');
      void queryClient.invalidateQueries({ queryKey: ['analysis', analysis.id] });
      void queryClient.invalidateQueries({ queryKey: ['analyses'] });
      void queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
    onError: (error: Error) => notify('error', 'Feedback not saved', error.message),
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (verdict) mutation.mutate();
      }}
    >
      <fieldset>
        <legend className="mb-2 text-[12.5px] text-muted">
          Your conclusion is stored separately from the automated verdict and is reviewed before it
          is ever used for training.
        </legend>
        <div className="flex flex-wrap gap-1.5">
          {VERDICTS.map((v) => (
            <label
              key={v}
              className={cx(
                'cursor-pointer rounded-md border px-2.5 py-1 text-[12.5px] transition-colors',
                verdict === v
                  ? 'border-accent bg-accent-soft text-text'
                  : 'border-line text-muted hover:text-text',
              )}
            >
              <input
                type="radio"
                name="verdict"
                value={v}
                checked={verdict === v}
                onChange={() => setVerdict(v)}
                className="sr-only"
              />
              {FEEDBACK_LABEL[v]}
            </label>
          ))}
        </div>
      </fieldset>
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        maxLength={2000}
        rows={2}
        placeholder="Notes (optional)"
        aria-label="Feedback notes"
        className="mt-3 w-full resize-y rounded-md border border-line bg-sunken px-3 py-2 text-[13px] text-text placeholder:text-faint focus:border-accent focus:outline-none"
      />
      <div className="mt-2 flex items-center justify-between gap-3">
        <span className="text-[12px] text-muted">
          {analysis.feedback
            ? `Last: ${FEEDBACK_LABEL[analysis.feedback.verdict]} · ${formatDateTime(analysis.feedback.createdAt)}`
            : 'No analyst feedback yet'}
        </span>
        <Button type="submit" size="sm" variant="primary" disabled={!verdict || mutation.isPending}>
          {mutation.isPending ? 'Saving…' : 'Save feedback'}
        </Button>
      </div>
    </form>
  );
}
