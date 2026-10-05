import type { AuthCheck, AuthenticationSummary, AuthState } from '../../models/analysis.js';
import { orgDomain } from '../parser/headers.js';

interface MethodResult {
  result: string;
  props: Record<string, string>;
}

/**
 * Parse one Authentication-Results header (RFC 8601) into method results.
 * Comments in parentheses are dropped; only the first result per method is
 * kept because that is what the receiving server evaluated for the message.
 */
export function parseAuthenticationResults(value: string): Record<string, MethodResult> {
  const withoutComments = value.replace(/\([^()]*\)/g, ' ');
  const statements = withoutComments.split(';').slice(1);
  const results: Record<string, MethodResult> = {};
  // Some producers (e.g. Exchange Online) omit the authserv-id, so the first
  // segment may itself be a method result.
  const first = withoutComments.split(';')[0] ?? '';
  if (/\b(spf|dkim|dmarc)\s*=/.test(first)) statements.unshift(first);

  for (const statement of statements) {
    const tokens = statement.trim().split(/\s+/).filter(Boolean);
    let current: string | undefined;
    for (const token of tokens) {
      const [key, ...rest] = token.split('=');
      const val = rest.join('=');
      if (!key || !val) continue;
      const lowerKey = key.toLowerCase();
      if (['spf', 'dkim', 'dmarc', 'arc', 'compauth', 'iprev', 'auth'].includes(lowerKey)) {
        current = lowerKey;
        if (!results[current]) results[current] = { result: val.toLowerCase(), props: {} };
        else current = undefined; // ignore later duplicates for the same method
      } else if (current) {
        results[current]!.props[lowerKey] = val.replace(/[";]/g, '').toLowerCase();
      }
    }
  }
  return results;
}

function stateFor(result: string | undefined): AuthState {
  if (!result) return 'not_present';
  if (result === 'pass') return 'pass';
  if (['fail', 'softfail', 'hardfail', 'permerror'].includes(result)) return 'fail';
  return 'unknown';
}

const DESCRIPTIONS: Record<'spf' | 'dkim' | 'dmarc', Record<AuthState, string>> = {
  spf: {
    pass: "The sending server is authorised by the envelope sender domain's SPF record.",
    fail: 'The sending server is not authorised to send for the envelope sender domain.',
    not_present: 'No SPF result was recorded by the receiving server.',
    unknown: 'SPF could not produce a definitive result (none, neutral or a temporary error).',
  },
  dkim: {
    pass: 'A DKIM signature on the message verified, so the signed content was not altered in transit.',
    fail: 'A DKIM signature was present but did not verify; the message may have been altered or forged.',
    not_present: 'No DKIM result was recorded by the receiving server.',
    unknown: 'DKIM did not produce a definitive result.',
  },
  dmarc: {
    pass: 'The visible From domain is authenticated by an aligned SPF or DKIM result.',
    fail: 'The visible From domain is not backed by aligned SPF or DKIM - a strong spoofing indicator.',
    not_present: 'No DMARC result was recorded by the receiving server.',
    unknown: 'DMARC did not produce a definitive result (e.g. the domain publishes no policy).',
  },
};

export function summariseAuthentication(input: {
  authResults: string[];
  receivedSpf: string[];
  dkimSignatures: string[];
  fromDomain?: string;
}): AuthenticationSummary {
  // The top-most header was added by the server closest to the recipient,
  // which is the only one an analyst should trust; lower ones can be forged.
  const top = input.authResults[0];
  const parsed = top ? parseAuthenticationResults(top) : {};
  const fromOrg = input.fromDomain ? orgDomain(input.fromDomain) : undefined;

  const build = (
    method: 'spf' | 'dkim' | 'dmarc',
    result: string | undefined,
    domain?: string,
  ): AuthCheck => {
    const state = stateFor(result);
    const aligned = domain && fromOrg ? orgDomain(domain) === fromOrg : undefined;
    return { state, result, domain, aligned, detail: DESCRIPTIONS[method][state] };
  };

  let spfResult = parsed.spf?.result;
  let spfDomain = parsed.spf?.props['smtp.mailfrom'] ?? parsed.spf?.props['smtp.helo'];
  if (!spfResult && input.receivedSpf[0]) {
    spfResult = /^\s*(\w+)/.exec(input.receivedSpf[0])?.[1]?.toLowerCase();
    spfDomain = /envelope-from=<?([^>;\s]+)/i.exec(input.receivedSpf[0])?.[1];
  }
  if (spfDomain?.includes('@')) spfDomain = spfDomain.split('@').pop();

  const dkim = build(
    'dkim',
    parsed.dkim?.result,
    parsed.dkim?.props['header.d'] ?? parsed.dkim?.props['header.i']?.split('@').pop(),
  );
  if (dkim.state === 'not_present' && input.dkimSignatures.length) {
    dkim.state = 'unknown';
    dkim.detail =
      'A DKIM-Signature header is present but no verification result was recorded. MailSherlock does not ' +
      'verify signatures offline, so the signature is unconfirmed.';
  }

  return {
    spf: build('spf', spfResult, spfDomain),
    dkim,
    dmarc: build(
      'dmarc',
      parsed.dmarc?.result,
      parsed.dmarc?.props['header.from'] ?? input.fromDomain,
    ),
    source: top ? top.slice(0, 400) : undefined,
    headerCount: input.authResults.length,
    dkimSignaturePresent: input.dkimSignatures.length > 0,
  };
}
