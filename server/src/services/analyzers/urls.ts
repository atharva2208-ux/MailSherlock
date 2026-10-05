import net from 'node:net';
import type { ExtractedUrl, Severity, UrlIndicator, UrlSource } from '../../models/analysis.js';
import type { HtmlInspection } from '../parser/html.js';
import { brandForOfficialDomain } from './brands.js';
import { assessHomoglyph, assessLookalike, domainInfo, SUSPICIOUS_TLDS } from './domain.js';

const URL_IN_TEXT = /\b(?:https?:\/\/|www\.)[^\s<>"'`()[\]{}]+/gi;
const DOMAIN_IN_TEXT = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/i;
const MAX_URLS = 300;

export const URL_SHORTENERS = new Set(
  'bit.ly t.co tinyurl.com goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at rb.gy t.ly tiny.cc s.id lnkd.in short.io bl.ink'.split(
    ' ',
  ),
);
const CREDENTIAL_PATH =
  /(?:log-?in|sign-?in|logon|verify|verification|validate|unlock|account|secure|update|webscr|password|passwd|auth|session|wp-(?:admin|includes|content)|confirm|recover)/i;
const REDIRECT_PARAMS =
  /^(?:url|u|redirect|redirect_uri|redir|next|target|dest|destination|continue|return|returnurl|goto|link|r)$/i;
const DOWNLOAD_EXT =
  /\.(?:exe|scr|js|jse|vbs|ps1|bat|cmd|msi|iso|img|zip|rar|7z|hta|lnk|apk|jar|html?)$/i;
const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function maxSeverity(values: Severity[]): Severity | 'none' {
  let best = -1;
  for (const value of values) best = Math.max(best, SEVERITY_ORDER.indexOf(value));
  return best < 0 ? 'none' : SEVERITY_ORDER[best]!;
}

function tryParse(value: string): URL | null {
  const candidate = /^www\./i.test(value) ? `http://${value}` : value;
  try {
    return new URL(candidate);
  } catch {
    return null;
  }
}

/** Decimal ("3232235777"), hex ("0x7f000001") or octal-dotted IPv4 hosts used to hide the destination. */
function isObfuscatedIp(host: string): boolean {
  if (/^\d{8,10}$/.test(host)) return true;
  if (/^0x[0-9a-f]{6,8}$/i.test(host)) return true;
  return (
    /^(?:0x[0-9a-f]+|0\d+|\d+)(?:\.(?:0x[0-9a-f]+|0\d+|\d+)){1,3}$/i.test(host) && !net.isIPv4(host)
  );
}

function indicator(id: string, label: string, severity: Severity): UrlIndicator {
  return { id, label, severity };
}

export function analyseUrl(
  url: string,
  source: UrlSource,
  anchorText?: string,
): ExtractedUrl | null {
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(url)?.[1]?.toLowerCase();
  const indicators: UrlIndicator[] = [];

  if (
    scheme === 'javascript' ||
    scheme === 'vbscript' ||
    (scheme === 'data' && /^data:text\/html/i.test(url))
  ) {
    indicators.push(indicator('dangerous_scheme', `Executable "${scheme}:" link`, 'high'));
    return {
      id: '',
      url: url.slice(0, 2048),
      source,
      host: '',
      registrableDomain: '',
      anchorText,
      indicators,
      risk: 'high',
    };
  }

  const parsed = tryParse(url);
  if (!parsed || !/^https?:$/.test(parsed.protocol)) return null;

  const rawAuthority = /^[a-z]+:\/\/([^/?#]*)/i.exec(url)?.[1] ?? '';
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const info = domainInfo(host);
  const official = brandForOfficialDomain(info.registrable);

  if (rawAuthority.includes('@')) {
    const shown = rawAuthority.split('@')[0];
    indicators.push(
      indicator(
        'userinfo',
        `"${shown}@" before the real host disguises the destination (${host})`,
        'high',
      ),
    );
  }
  // The WHATWG parser canonicalises numeric hosts (3232235777 -> 192.168.0.1),
  // so the obfuscation check must look at the authority as written.
  if (isObfuscatedIp(rawAuthority.split('@').pop()?.split(':')[0] ?? '')) {
    indicators.push(
      indicator(
        'obfuscated_ip',
        `IP address written in decimal/hex/octal form (resolves to ${host})`,
        'high',
      ),
    );
  } else if (info.isIp)
    indicators.push(indicator('ip_host', 'Link points to a raw IP address', 'high'));
  if (URL_SHORTENERS.has(info.registrable) || URL_SHORTENERS.has(host)) {
    indicators.push(indicator('shortener', 'URL shortener hides the final destination', 'medium'));
  }
  const tld = info.publicSuffix.split('.').pop() ?? '';
  if (SUSPICIOUS_TLDS.has(tld))
    indicators.push(indicator('suspicious_tld', `High-abuse top-level domain ".${tld}"`, 'medium'));

  const homoglyph = assessHomoglyph(host);
  if (homoglyph) {
    indicators.push(
      indicator(
        'idn',
        homoglyph.mixedScript
          ? `Internationalised domain mixing ${homoglyph.scripts.join(' + ')} scripts (renders as ${homoglyph.unicodeHost})`
          : `Internationalised domain (renders as ${homoglyph.unicodeHost})`,
        homoglyph.mixedScript ? 'critical' : 'medium',
      ),
    );
  }
  const lookalike = assessLookalike(host);
  if (lookalike) {
    indicators.push(
      indicator(
        'lookalike',
        `Imitates ${lookalike.brand.name} (${lookalike.technique.replace(/_/g, ' ')})`,
        lookalike.confidence >= 0.9 ? 'critical' : 'high',
      ),
    );
  }

  const depth = info.subdomain ? info.subdomain.split('.').length : 0;
  if (depth >= 4)
    indicators.push(indicator('deep_subdomains', `${depth} levels of subdomains`, 'low'));
  if (url.length > 200)
    indicators.push(indicator('long_url', `Unusually long URL (${url.length} characters)`, 'low'));
  if (/%[0-9a-f]{2}/i.test(rawAuthority) || (url.match(/%[0-9a-f]{2}/gi)?.length ?? 0) > 12) {
    indicators.push(indicator('encoded', 'Heavy percent-encoding obscures the URL', 'medium'));
  }
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    indicators.push(indicator('port', `Non-standard port ${parsed.port}`, 'low'));
  }

  let decodedPath = parsed.pathname;
  try {
    decodedPath = decodeURIComponent(parsed.pathname);
  } catch {
    // keep the raw path when it contains invalid escapes
  }
  if (!official && CREDENTIAL_PATH.test(decodedPath + parsed.search)) {
    indicators.push(
      indicator('credential_path', 'Login/verification-style path on a non-brand domain', 'medium'),
    );
  }
  if (!official && parsed.protocol === 'http:' && CREDENTIAL_PATH.test(decodedPath)) {
    indicators.push(
      indicator('insecure_credential', 'Credential-style page served without HTTPS', 'low'),
    );
  }
  for (const [key, value] of parsed.searchParams) {
    if (REDIRECT_PARAMS.test(key) && /^(?:https?:)?\/\//i.test(value)) {
      const target = tryParse(value.startsWith('//') ? `https:${value}` : value);
      if (target && domainInfo(target.hostname).registrable !== info.registrable) {
        indicators.push(
          indicator(
            'redirect',
            `Redirects to another domain (${target.hostname})`,
            official ? 'medium' : 'low',
          ),
        );
        break;
      }
    }
  }
  if (DOWNLOAD_EXT.test(parsed.pathname)) {
    indicators.push(
      indicator(
        'download',
        `Direct link to a "${parsed.pathname.split('.').pop()}" file`,
        'medium',
      ),
    );
  }

  if (anchorText && source === 'anchor') {
    const shown = DOMAIN_IN_TEXT.exec(anchorText)?.[1];
    if (shown && !/^\d+(?:\.\d+)+$/.test(shown)) {
      const shownDomain = domainInfo(shown).registrable;
      if (shownDomain && shownDomain !== info.registrable && shownDomain.includes('.')) {
        indicators.push(
          indicator('anchor_mismatch', `Link text shows ${shown} but points to ${host}`, 'high'),
        );
      }
    }
  }

  return {
    id: '',
    url: url.slice(0, 2048),
    source,
    host,
    registrableDomain: info.registrable,
    unicodeHost: info.isIdn ? info.unicodeHost : undefined,
    anchorText: anchorText?.slice(0, 300) || undefined,
    indicators,
    risk: maxSeverity(indicators.map((i) => i.severity)),
  };
}

export function extractUrls(text: string, html?: HtmlInspection): ExtractedUrl[] {
  const candidates: { url: string; source: UrlSource; anchorText?: string }[] = [];
  for (const anchor of html?.anchors ?? []) {
    if (/^(?:mailto|tel|cid|#)/i.test(anchor.href) || !anchor.href) continue;
    candidates.push({ url: anchor.href, source: 'anchor', anchorText: anchor.text });
  }
  for (const form of html?.forms ?? [])
    if (form.action) candidates.push({ url: form.action, source: 'form' });
  for (const match of text.matchAll(URL_IN_TEXT)) {
    candidates.push({ url: match[0].replace(/[.,;:!?)\]}>'"]+$/, ''), source: 'text' });
  }
  for (const src of html?.images ?? [])
    if (/^https?:/i.test(src)) candidates.push({ url: src, source: 'image' });

  const seen = new Map<string, ExtractedUrl>();
  for (const candidate of candidates) {
    if (seen.size >= MAX_URLS) break;
    const key = `${candidate.source === 'image' ? 'img:' : ''}${candidate.url}`;
    const existing = seen.get(key);
    if (existing) {
      // An anchor carries more context (its visible text) than a bare text match.
      if (candidate.source === 'anchor' && existing.source === 'text')
        seen.set(key, {
          ...analyseUrl(candidate.url, 'anchor', candidate.anchorText)!,
          id: existing.id,
        });
      continue;
    }
    const analysed = analyseUrl(candidate.url, candidate.source, candidate.anchorText);
    if (analysed) seen.set(key, { ...analysed, id: `u${seen.size + 1}` });
  }
  return [...seen.values()];
}
