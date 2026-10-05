import { domainToUnicode } from 'node:url';
import net from 'node:net';
import { parse } from 'tldts';
import { BRANDS, brandForOfficialDomain, type Brand } from './brands.js';
import { hasNonAscii, scriptsIn, skeleton, unicodeSkeleton } from './confusables.js';

export const FREE_MAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'yahoo.com',
  'ymail.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'protonmail.com',
  'proton.me',
  'gmx.com',
  'gmx.net',
  'mail.com',
  'yandex.com',
  'zoho.com',
  'rediffmail.com',
  'tutanota.com',
]);

/** TLDs with persistently high abuse rates in public phishing feeds. */
export const SUSPICIOUS_TLDS = new Set(
  'top xyz icu tk ml ga cf gq buzz cyou rest click link work fit shop live loan zip mov monster sbs cfd quest bond lol support country kim cam surf'.split(
    ' ',
  ),
);

export interface DomainInfo {
  host: string;
  unicodeHost: string;
  registrable: string;
  label: string;
  subdomain: string;
  publicSuffix: string;
  isIp: boolean;
  isIdn: boolean;
}

export function domainInfo(rawHost: string): DomainInfo {
  const host = rawHost
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^\[|\]$/g, '');
  const isIp = net.isIP(host) !== 0;
  const parsed = parse(host, { allowPrivateDomains: false });
  const registrable = isIp ? host : (parsed.domain ?? host);
  return {
    host,
    unicodeHost: isIp ? host : domainToUnicode(host) || host,
    registrable,
    label: isIp ? host : (parsed.domainWithoutSuffix ?? registrable.split('.')[0] ?? ''),
    subdomain: parsed.subdomain ?? '',
    publicSuffix: parsed.publicSuffix ?? '',
    isIp,
    isIdn: host.split('.').some((part) => part.startsWith('xn--')) || hasNonAscii(host),
  };
}

/** Levenshtein distance with an early exit once `max` is exceeded. */
export function levenshtein(a: string, b: string, max = Infinity): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const value = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost);
      current.push(value);
      rowMin = Math.min(rowMin, value);
    }
    if (rowMin > max) return max + 1;
    previous = current;
  }
  return previous[b.length]!;
}

export type LookalikeTechnique =
  'homoglyph' | 'character_substitution' | 'typosquat' | 'brand_embedded' | 'brand_in_subdomain';

export interface LookalikeMatch {
  brand: Brand;
  keyword: string;
  technique: LookalikeTechnique;
  confidence: number;
  detail: string;
}

const TECHNIQUE_TEXT: Record<LookalikeTechnique, string> = {
  homoglyph: 'uses Unicode characters from another script that render like Latin letters',
  character_substitution: 'substitutes look-alike characters (e.g. 0 for o, 1 for l, rn for m)',
  typosquat: 'differs from the brand by a small number of character edits',
  brand_embedded: 'embeds the brand name inside an unrelated registered domain',
  brand_in_subdomain: 'places the brand name in a subdomain of an unrelated domain',
};

/**
 * Compare a hostname against protected brands. Returns the strongest match,
 * or null when the host is unrelated or is an official domain of the brand.
 */
export function assessLookalike(rawHost: string): LookalikeMatch | null {
  const info = domainInfo(rawHost);
  if (info.isIp || !info.label) return null;
  const official = brandForOfficialDomain(info.registrable);

  const unicodeLabel = domainToUnicode(info.label) || info.label;
  const asciiLabel = info.label;
  const unicodeSkel = unicodeSkeleton(unicodeLabel);
  const fullSkel = skeleton(unicodeLabel);
  const rawTokens = asciiLabel.split(/[-_]/).filter(Boolean);
  const subdomainTokens = info.subdomain.split(/[.\-_]/).filter(Boolean);

  let best: LookalikeMatch | null = null;
  const consider = (
    brand: Brand,
    keyword: string,
    technique: LookalikeTechnique,
    confidence: number,
  ) => {
    if (official === brand) return;
    if (!best || confidence > best.confidence) {
      best = {
        brand,
        keyword,
        technique,
        confidence,
        detail: `${info.unicodeHost} ${TECHNIQUE_TEXT[technique]} to imitate ${brand.name} (${keyword}).`,
      };
    }
  };

  for (const brand of BRANDS) {
    for (const keyword of brand.keywords) {
      if (hasNonAscii(unicodeLabel) && unicodeSkel === keyword) {
        consider(brand, keyword, 'homoglyph', 0.97);
        continue;
      }
      if (asciiLabel !== keyword && fullSkel === keyword) {
        consider(brand, keyword, 'character_substitution', 0.95);
        continue;
      }
      const maxEdits = keyword.length >= 8 ? 2 : 1;
      if (keyword.length >= 5 && asciiLabel.length >= 5 && asciiLabel !== keyword) {
        const distance = levenshtein(asciiLabel, keyword, maxEdits);
        if (distance <= maxEdits) {
          consider(brand, keyword, 'typosquat', distance === 1 ? 0.88 : 0.8);
          continue;
        }
      }
      if (rawTokens.length > 1) {
        for (const token of rawTokens) {
          if (token === keyword) consider(brand, keyword, 'brand_embedded', 0.82);
          else if (keyword.length >= 5 && skeleton(token) === keyword)
            consider(brand, keyword, 'character_substitution', 0.93);
          else if (keyword.length >= 6 && token.length >= 6 && levenshtein(token, keyword, 1) === 1)
            consider(brand, keyword, 'typosquat', 0.75);
        }
      } else if (
        keyword.length >= 5 &&
        asciiLabel.length > keyword.length + 2 &&
        asciiLabel.includes(keyword)
      ) {
        consider(brand, keyword, 'brand_embedded', 0.7);
      }
      if (subdomainTokens.includes(keyword)) consider(brand, keyword, 'brand_in_subdomain', 0.8);
    }
  }
  return best;
}

export interface HomoglyphAssessment {
  unicodeHost: string;
  scripts: string[];
  mixedScript: boolean;
  skeleton: string;
}

/** Report IDN hosts whose labels mix scripts - the core homoglyph signal. */
export function assessHomoglyph(rawHost: string): HomoglyphAssessment | null {
  const info = domainInfo(rawHost);
  if (!info.isIdn) return null;
  const labels = info.unicodeHost.split('.');
  const scripts = new Set<string>();
  let mixedScript = false;
  for (const label of labels) {
    const labelScripts = scriptsIn(label);
    labelScripts.forEach((s) => scripts.add(s));
    if (labelScripts.length > 1) mixedScript = true;
  }
  return {
    unicodeHost: info.unicodeHost,
    scripts: [...scripts],
    mixedScript,
    skeleton: unicodeSkeleton(info.unicodeHost),
  };
}
