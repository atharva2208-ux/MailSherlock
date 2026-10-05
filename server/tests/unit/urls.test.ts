import { describe, expect, it } from 'vitest';
import { analyseUrl, extractUrls } from '../../src/services/analyzers/urls.js';

const ids = (url: string, anchor?: string) =>
  analyseUrl(url, anchor ? 'anchor' : 'text', anchor)?.indicators.map((i) => i.id) ?? [];

describe('URL analysis', () => {
  it('flags "@" userinfo and resolves the real host', () => {
    const result = analyseUrl('https://google.com@evil.example/login', 'text');
    expect(result?.host).toBe('evil.example');
    expect(result?.indicators.map((i) => i.id)).toContain('userinfo');
    expect(result?.risk).toBe('high');
  });

  it('flags raw and obfuscated IP hosts', () => {
    expect(ids('http://203.0.113.5/a')).toContain('ip_host');
    expect(ids('http://3232235777/x')).toContain('obfuscated_ip');
  });

  it('flags shorteners, suspicious TLDs, redirects, downloads and executable schemes', () => {
    expect(ids('https://bit.ly/abc')).toContain('shortener');
    expect(ids('https://pay-now.top/x')).toContain('suspicious_tld');
    expect(ids('https://www.google.com/url?q=x&url=https://evil.example/p')).toContain('redirect');
    expect(ids('https://cdn.example.net/files/invoice.exe')).toContain('download');
    expect(analyseUrl('javascript:alert(1)', 'anchor')?.indicators[0]?.id).toBe('dangerous_scheme');
  });

  it('detects misleading anchor text but not matching text', () => {
    expect(ids('https://evil.example/login', 'https://account.microsoft.com/security')).toContain(
      'anchor_mismatch',
    );
    expect(ids('https://github.com/settings', 'github.com/settings')).not.toContain(
      'anchor_mismatch',
    );
  });

  it('does not flag credential paths on official brand domains', () => {
    expect(ids('https://github.com/password_reset/abc')).not.toContain('credential_path');
    expect(ids('https://login.secure-example.top/verify')).toContain('credential_path');
  });

  it('extracts and deduplicates URLs from text and HTML, preferring anchor context', () => {
    const urls = extractUrls('See https://example.org/a. Also https://example.org/a', {
      anchors: [{ href: 'https://example.org/a', text: 'Example' }],
      forms: [
        {
          action: 'https://collect.example.net/post',
          method: 'post',
          hasPasswordField: true,
          inputNames: [],
        },
      ],
      images: ['https://tracker.example.net/p.gif'],
      hiddenText: [],
      scriptCount: 0,
      iframeCount: 0,
    });
    expect(urls.map((u) => [u.source, u.url])).toEqual([
      ['anchor', 'https://example.org/a'],
      ['form', 'https://collect.example.net/post'],
      ['image', 'https://tracker.example.net/p.gif'],
    ]);
  });

  it('never throws on malformed URLs', () => {
    expect(() =>
      extractUrls('http://[::1 http://%%%% https://bit.ly]x https://', undefined),
    ).not.toThrow();
  });
});
