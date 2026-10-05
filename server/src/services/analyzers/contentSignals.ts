import type { TextSpan } from '../../models/analysis.js';

/**
 * Social-engineering intents. Each phrase has a weight reflecting how
 * specific it is to manipulation; generic words carry little weight on their
 * own and only become a finding when they co-occur with other intents or a
 * call to action (see `analyseContent`).
 */
export type IntentId =
  | 'urgency'
  | 'account_threat'
  | 'credential_request'
  | 'mfa_request'
  | 'payment_request'
  | 'bank_change'
  | 'gift_card'
  | 'secrecy'
  | 'authority'
  | 'prize_lure'
  | 'delivery_lure'
  | 'job_lure';

interface Phrase {
  pattern: RegExp;
  weight: number;
}

const p = (source: string, weight: number): Phrase => ({
  pattern: new RegExp(source, 'gi'),
  weight,
});

export const INTENTS: Record<IntentId, { label: string; phrases: Phrase[] }> = {
  urgency: {
    label: 'Urgency / time pressure',
    phrases: [
      p(String.raw`\bwithin\s+(?:the\s+next\s+)?\d{1,3}\s*(?:hours?|hrs?|minutes?|days?)\b`, 1.5),
      p(String.raw`\b(?:immediately|right away|without delay|as soon as possible|asap)\b`, 1),
      p(
        String.raw`\b(?:urgent(?:ly)?|final (?:notice|warning|reminder)|last (?:chance|warning))\b`,
        1,
      ),
      p(String.raw`\b(?:act now|respond now|before it(?:'s| is) too late)\b`, 1.2),
      p(String.raw`\b(?:today|by end of day|before \d{1,2}(?::\d\d)?\s*(?:am|pm))\b`, 0.4),
      p(String.raw`\b(?:expires?|expiring|deadline)\b`, 0.4),
      p(String.raw`\blimited time\b`, 0.3),
    ],
  },
  account_threat: {
    label: 'Account suspension or loss threat',
    phrases: [
      p(
        String.raw`\b(?:will|shall)\s+be\s+(?:permanently\s+)?(?:suspended|locked|closed|disabled|deactivated|deleted|terminated|blocked|restricted|lost)\b`,
        2,
      ),
      p(
        String.raw`\b(?:has|have)\s+been\s+(?:temporarily\s+)?(?:suspended|limited|restricted|locked|blocked|compromised|deactivated)\b`,
        1.5,
      ),
      p(
        String.raw`\bpermanent(?:ly)?\s+(?:account\s+)?(?:closure|closed|disabled|deleted|suspension)\b`,
        1.5,
      ),
      p(
        String.raw`\b(?:unusual|suspicious|unauthori[sz]ed)\s+(?:sign-?in\s+|login\s+)?(?:activity|access|attempts?|log-?ins?)\b`,
        1,
      ),
      p(
        String.raw`\b(?:messages?|emails?)\s+(?:are being held|will be (?:deleted|rejected|lost))\b`,
        1.5,
      ),
      p(String.raw`\b(?:failure to (?:do so|comply|respond|verify))\b`, 1.5),
      p(String.raw`\b(?:returned to (?:the )?sender|legal action)\b`, 1),
    ],
  },
  credential_request: {
    label: 'Credential request',
    phrases: [
      p(
        String.raw`\b(?:verify|confirm|validate|update|re-?enter)\s+your\s+(?:account|identity|credentials|password|login|log-?in details|information|details|billing information|email)\b`,
        2,
      ),
      p(
        String.raw`\b(?:enter|provide|submit|type)\s+your\s+(?:password|credentials|username|login|pin|ssn)\b`,
        2.5,
      ),
      p(String.raw`\b(?:username|email)\s+and\s+password\b`, 2),
      p(String.raw`\bsign\s*in\s+(?:below|here|now|with your)\b`, 1.2),
      p(String.raw`\b(?:confirm|verify)\s+your\s+identity\b`, 1),
      p(String.raw`\b(?:restore|unlock|reactivate)\s+(?:full\s+)?(?:access|your account)\b`, 1),
      p(String.raw`\b(?:card details|card number|cvv|billing information)\b`, 1.5),
    ],
  },
  mfa_request: {
    label: 'MFA / one-time code request',
    phrases: [
      p(
        String.raw`\bapprove\s+(?:the\s+)?(?:mfa|push|sign-?in|authentication|login)\s+(?:prompt|request|notification)\b`,
        2.5,
      ),
      p(
        String.raw`\b(?:send|share|reply with|provide|forward)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:otp|one[- ]time (?:code|password)|verification code|security code|2fa code)\b`,
        3,
      ),
      p(String.raw`\b(?:re-?register|re-?enrol+)\s+(?:your\s+)?(?:multi-factor|mfa|2fa)\b`, 2),
    ],
  },
  payment_request: {
    label: 'Payment request',
    phrases: [
      p(
        String.raw`\b(?:wire transfer|bank transfer|process(?:ing)? (?:a|the|an urgent)? ?(?:payment|wire))\b`,
        1.5,
      ),
      p(
        String.raw`\b(?:invoice|payment)\s+(?:is\s+)?(?:\d+\s+days\s+)?(?:overdue|outstanding|past due)\b`,
        1.5,
      ),
      p(
        String.raw`\b(?:pay|settle)\s+(?:the|a|this)\s+(?:\w+\s+)?(?:fee|invoice|balance|amount|duty)\b`,
        1.2,
      ),
      p(
        String.raw`\b(?:customs|redelivery|processing|registration|release)\s+(?:fee|duty|charge)\b`,
        1.5,
      ),
      p(String.raw`\blate (?:fees?|charges?)\b`, 0.8),
    ],
  },
  bank_change: {
    label: 'Changed banking details',
    phrases: [
      p(
        String.raw`\b(?:bank(?:ing)?|account|payment)\s+(?:details|information|instructions)\s+(?:have|has)\s+(?:been\s+)?changed\b`,
        3,
      ),
      p(
        String.raw`\b(?:new|updated)\s+(?:bank(?:ing)?|account)\s+(?:details|account|information)\b`,
        2,
      ),
    ],
  },
  gift_card: {
    label: 'Gift card request',
    phrases: [
      p(
        String.raw`\b(?:\d+\s+|some\s+)?(?:\$?\d+\s+)?(?:apple|google play|itunes|amazon|steam|visa)?\s*gift\s*cards?\b`,
        2.5,
      ),
      p(String.raw`\b(?:scratch|send me)\s+(?:the\s+)?(?:codes?|pictures)\b`, 2),
    ],
  },
  secrecy: {
    label: 'Secrecy / isolation',
    phrases: [
      p(String.raw`\bkeep\s+(?:this|it)\s+(?:confidential|between us|private|quiet)\b`, 2.5),
      p(String.raw`\bdo(?:n't| not)\s+(?:discuss|tell|share|mention)\b`, 1.5),
      p(
        String.raw`\b(?:can(?:'t|not)\s+(?:talk|take calls)|in a (?:board )?meeting|reply by email only)\b`,
        1.5,
      ),
      p(String.raw`\bare you (?:at your desk|available)\b`, 1.2),
    ],
  },
  authority: {
    label: 'Authority impersonation',
    phrases: [
      p(String.raw`\b(?:ceo|cfo|managing director|chief executive|president)\b`, 1),
      p(
        String.raw`\b(?:it (?:service desk|helpdesk|help desk|department|support)|system administrator|security team)\b`,
        1,
      ),
      p(String.raw`\b(?:tax department|income tax|irs|government|police|court)\b`, 0.8),
    ],
  },
  prize_lure: {
    label: 'Prize / reward lure',
    phrases: [
      p(String.raw`\b(?:you(?:'ve| have)\s+(?:won|been selected)|congratulations[!,]?\s+you)\b`, 2),
      p(String.raw`\bclaim\s+(?:your\s+)?(?:prize|reward|gift|refund)\b`, 2),
      p(String.raw`\b(?:lottery|lucky (?:winner|draw)|reward draw|sweepstakes)\b`, 1.5),
      p(String.raw`\b(?:eligible for (?:a|an)\s+(?:\w+\s+)?refund)\b`, 1.5),
    ],
  },
  delivery_lure: {
    label: 'Delivery problem lure',
    phrases: [
      p(
        String.raw`\b(?:parcel|package|shipment|delivery)\s+(?:could not be delivered|is on hold|was returned|failed|has been held)\b`,
        2,
      ),
      p(String.raw`\b(?:schedule|arrange)\s+(?:a\s+)?(?:new\s+)?(?:re-?)?delivery\b`, 1),
      p(String.raw`\bno one was available\b`, 1),
    ],
  },
  job_lure: {
    label: 'Employment scam lure',
    phrases: [
      p(String.raw`\b(?:work from home|remote data entry|part[- ]time job)\b`, 1.2),
      p(String.raw`\b(?:refundable\s+)?registration fee\b`, 2),
      p(String.raw`\bpaying\s+(?:rs\.?|\$|inr)\s?[\d,]+\s+per\s+(?:day|hour)\b`, 1.5),
    ],
  },
};

export interface IntentResult {
  id: IntentId;
  label: string;
  score: number;
  spans: TextSpan[];
}

export interface ContentAnalysis {
  intents: Partial<Record<IntentId, IntentResult>>;
  callToAction: boolean;
  /** Raw (pre-context) scores, kept for transparency in tests and debugging. */
  rawScores: Partial<Record<IntentId, number>>;
}

const MAX_SPANS_PER_INTENT = 12;

function overlaps(spans: TextSpan[], start: number, end: number): boolean {
  return spans.some((s) => start < s.end && end > s.start);
}

/**
 * Weighted, context-aware intent scoring. Keywords alone are weak evidence:
 * "limited time" in a newsletter is not urgency in the phishing sense, but
 * "within 24 hours" next to "will be suspended" and a login link is.
 */
export function analyseContent(
  text: string,
  subject: string,
  context: { callToAction: boolean },
): ContentAnalysis {
  const intents: Partial<Record<IntentId, IntentResult>> = {};
  const rawScores: Partial<Record<IntentId, number>> = {};
  const haystack = text.slice(0, 50_000);
  const subjectLower = subject.toLowerCase();

  for (const [id, intent] of Object.entries(INTENTS) as [IntentId, (typeof INTENTS)[IntentId]][]) {
    const spans: TextSpan[] = [];
    let score = 0;
    for (const phrase of intent.phrases) {
      phrase.pattern.lastIndex = 0;
      let matchedThisPhrase = false;
      for (const match of haystack.matchAll(phrase.pattern)) {
        const start = match.index ?? 0;
        const end = start + match[0].length;
        if (!match[0].trim() || overlaps(spans, start, end)) continue;
        if (spans.length < MAX_SPANS_PER_INTENT) spans.push({ start, end, text: match[0] });
        matchedThisPhrase = true;
      }
      phrase.pattern.lastIndex = 0;
      // Repetition of the same phrase adds little; distinct phrases add their weight.
      if (matchedThisPhrase || phrase.pattern.test(subjectLower)) score += phrase.weight;
      phrase.pattern.lastIndex = 0;
    }
    if (score > 0) {
      rawScores[id] = score;
      intents[id] = {
        id,
        label: intent.label,
        score,
        spans: spans.sort((a, b) => a.start - b.start),
      };
    }
  }

  const has = (id: IntentId) => (intents[id]?.score ?? 0) > 0;
  const boost = (id: IntentId, factor: number) => {
    const item = intents[id];
    if (item) item.score = Math.round(item.score * factor * 100) / 100;
  };

  const pressure = has('account_threat') || has('urgency');
  const ask =
    has('credential_request') ||
    has('mfa_request') ||
    has('payment_request') ||
    has('gift_card') ||
    has('bank_change');
  if (context.callToAction) boost('credential_request', 1.3);
  if (has('account_threat')) boost('credential_request', 1.2);
  if (has('secrecy') || pressure) {
    boost('payment_request', 1.3);
    boost('gift_card', 1.2);
    boost('bank_change', 1.2);
  }
  // Urgency only matters when it pushes the reader toward an action.
  if (!ask && !has('account_threat')) boost('urgency', 0.5);
  if (!ask && !has('secrecy')) boost('authority', 0.5);

  return { intents, callToAction: context.callToAction, rawScores };
}
