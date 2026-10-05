import { describe, expect, it } from 'vitest';
import {
  assessHomoglyph,
  assessLookalike,
  levenshtein,
} from '../../src/services/analyzers/domain.js';
import { skeleton } from '../../src/services/analyzers/confusables.js';

describe('levenshtein', () => {
  it('computes edit distance with early exit', () => {
    expect(levenshtein('paypal', 'paypa1')).toBe(1);
    expect(levenshtein('amazon', 'arnazon')).toBe(2);
    expect(levenshtein('microsoft', 'zzzzzzzzzzzz', 2)).toBe(3);
  });
});

describe('lookalike domains', () => {
  it.each([
    ['micr0soft.com', 'Microsoft', 'character_substitution'],
    ['paypa1.com', 'PayPal', 'character_substitution'],
    ['arnazon.com', 'Amazon', 'character_substitution'],
    ['g00gle.com', 'Google', 'character_substitution'],
    ['gooogle.com', 'Google', 'typosquat'],
    ['paypal-resolution-center.xyz', 'PayPal', 'brand_embedded'],
    ['paypal.com.secure-login.top', 'PayPal', 'brand_in_subdomain'],
    ['login.micr0soft-accountprotection.com', 'Microsoft', 'character_substitution'],
  ])('%s imitates %s via %s', (host, brand, technique) => {
    const match = assessLookalike(host);
    expect(match?.brand.name).toBe(brand);
    expect(match?.technique).toBe(technique);
  });

  it.each([
    'www.paypal.com',
    'accounts.google.com',
    'github.com',
    'amazon.in',
    'purchase-orders.com',
    'zoominfo.com',
    'example.org',
  ])('does not flag %s', (host) => {
    expect(assessLookalike(host)).toBeNull();
  });
});

describe('homoglyphs', () => {
  it('detects mixed-script IDN domains and recovers the imitated name', () => {
    const result = assessHomoglyph('xn--microsft-sbh.com'); // "microsоft" with Cyrillic о
    expect(result?.mixedScript).toBe(true);
    expect(result?.scripts).toEqual(['Latin', 'Cyrillic']);
    expect(result?.skeleton).toBe('microsoft.com');
    expect(assessLookalike('xn--microsft-sbh.com')?.technique).toBe('homoglyph');
  });

  it('does not treat single-script IDNs as mixed', () => {
    expect(assessHomoglyph('xn--e1afmkfd.xn--p1ai')?.mixedScript).toBe(false); // пример.рф
    expect(assessHomoglyph('example.com')).toBeNull();
  });

  it('normalises confusables and digit substitutions', () => {
    expect(skeleton('рaypa1')).toBe('paypal');
    expect(skeleton('rnicrosoft')).toBe('microsoft');
  });
});
