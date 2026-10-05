import { describe, expect, it } from 'vitest';
import { analyseContent } from '../../src/services/analyzers/contentSignals.js';

describe('content intent analysis', () => {
  const phishing =
    'Your account will be suspended within 24 hours unless you verify your credentials immediately.';

  it('scores co-occurring intents and returns spans that index into the text', () => {
    const result = analyseContent(phishing, '', { callToAction: true });
    expect(result.intents.account_threat).toBeDefined();
    expect(result.intents.credential_request).toBeDefined();
    for (const intent of Object.values(result.intents)) {
      for (const span of intent!.spans)
        expect(phishing.slice(span.start, span.end)).toBe(span.text);
    }
    // A call to action and an account threat amplify the credential request.
    expect(result.intents.credential_request!.score).toBeGreaterThan(
      result.rawScores.credential_request!,
    );
  });

  it('damps urgency that is not attached to any request', () => {
    const result = analyseContent(
      'Limited time: 20% off this week only. Hurry, sale expires Sunday!',
      '',
      { callToAction: true },
    );
    expect(result.intents.urgency!.score).toBeLessThan(result.rawScores.urgency!);
    expect(result.intents.credential_request).toBeUndefined();
  });

  it('recognises business email compromise phrasing', () => {
    const result = analyseContent(
      'Are you at your desk? I need you to buy four gift cards and send me the codes. Keep this confidential.',
      '',
      { callToAction: false },
    );
    expect(result.intents.gift_card).toBeDefined();
    expect(result.intents.secrecy).toBeDefined();
  });

  it('returns nothing for ordinary conversation', () => {
    const result = analyseContent(
      'Hi team, the meeting notes from Tuesday are attached. See you at lunch.',
      'notes',
      { callToAction: false },
    );
    expect(Object.keys(result.intents)).toHaveLength(0);
  });
});
