import { CheckCircle2, CircleDashed, HelpCircle, XCircle } from 'lucide-react';
import type { AuthCheck, AuthenticationSummary } from '../../types';

const STATE = {
  pass: { label: 'Pass', icon: CheckCircle2, color: 'var(--safe)' },
  fail: { label: 'Fail', icon: XCircle, color: 'var(--critical)' },
  not_present: { label: 'Not present', icon: CircleDashed, color: 'var(--faint)' },
  unknown: { label: 'Unknown', icon: HelpCircle, color: 'var(--medium)' },
} as const;

const NAMES = { spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC' } as const;

function Row({ name, check }: { name: keyof typeof NAMES; check: AuthCheck }) {
  const state = STATE[check.state];
  return (
    <div className="grid gap-x-4 gap-y-1 border-b border-line px-4 py-3 last:border-b-0 sm:grid-cols-[90px_130px_1fr]">
      <p className="font-semibold">{NAMES[name]}</p>
      <p className="flex items-center gap-1.5 font-medium" style={{ color: state.color }}>
        <state.icon size={15} />
        {state.label}
        {check.result && check.result !== check.state && (
          <span className="font-mono text-[11.5px] text-muted">({check.result})</span>
        )}
      </p>
      <div className="min-w-0 text-[13px]">
        <p>{check.detail}</p>
        {(check.domain || check.aligned !== undefined) && (
          <p className="mt-0.5 text-[12px] text-muted">
            {check.domain && (
              <>
                Domain <code className="font-mono">{check.domain}</code>
              </>
            )}
            {check.aligned !== undefined && (
              <>
                {' '}
                ·{' '}
                {check.aligned ? (
                  'aligned with From'
                ) : (
                  <span className="text-high">not aligned with From</span>
                )}
              </>
            )}
          </p>
        )}
      </div>
    </div>
  );
}

export function AuthPanel({
  auth,
  compact = false,
}: {
  auth: AuthenticationSummary;
  compact?: boolean;
}) {
  if (compact) {
    return (
      <ul className="space-y-1.5 text-[13px]">
        {(['spf', 'dkim', 'dmarc'] as const).map((k) => {
          const state = STATE[auth[k].state];
          return (
            <li key={k} className="flex items-center justify-between gap-3">
              <span className="font-medium">{NAMES[k]}</span>
              <span className="flex items-center gap-1.5" style={{ color: state.color }}>
                <state.icon size={14} />
                {state.label}
              </span>
            </li>
          );
        })}
      </ul>
    );
  }
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-line bg-surface">
        <Row name="spf" check={auth.spf} />
        <Row name="dkim" check={auth.dkim} />
        <Row name="dmarc" check={auth.dmarc} />
      </div>
      <div className="rounded-lg border border-line bg-surface p-4 text-[13px]">
        <p className="font-semibold">Source of these results</p>
        {auth.source ? (
          <>
            <p className="mt-1 text-muted">
              Taken from the top-most of {auth.headerCount} Authentication-Results header
              {auth.headerCount === 1 ? '' : 's'} - the one added by the server nearest the
              recipient. Lower headers can be forged by the sender and are ignored.
            </p>
            <pre className="mt-3 overflow-x-auto rounded-md bg-sunken p-3 font-mono text-[12px] whitespace-pre-wrap">
              {auth.source}
            </pre>
          </>
        ) : (
          <p className="mt-1 text-muted">
            The message has no Authentication-Results header, so no result is shown rather than
            guessing. Export the message from the recipient mailbox with full headers to evaluate
            SPF, DKIM and DMARC.
            {auth.dkimSignaturePresent &&
              ' A DKIM-Signature is present but MailSherlock does not verify signatures offline.'}
          </p>
        )}
      </div>
    </div>
  );
}
