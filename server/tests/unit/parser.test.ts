import { describe, expect, it } from 'vitest';
import { parseEmail } from '../../src/services/parser/parseEmail.js';
import { AppError } from '../../src/utils/errors.js';
import { fixture, sample } from '../helpers.js';

describe('parseEmail', () => {
  it('decodes encoded headers, quoted-printable bodies and address fields', async () => {
    const parsed = await parseEmail(sample('phishing/microsoft-account.eml'));
    expect(parsed.metadata.subject).toBe('Action Required: Unusual sign-in activity');
    expect(parsed.metadata.from).toEqual({
      name: 'Microsoft Account Team',
      address: 'no-reply@micr0soft-accountprotection.com',
      domain: 'micr0soft-accountprotection.com',
    });
    expect(parsed.metadata.replyTo?.[0]?.address).toBe('recovery.desk.2291@gmail-support-mail.com');
    expect(parsed.metadata.returnPath).toBe('bounce-7731@mailer.secure-notify-center.top');
    expect(parsed.body.text).toContain('Your account will be suspended within 24 hours');
    expect(parsed.body.textSource).toBe('plain');
    expect(parsed.mimeStructure.map((p) => p.contentType)).toEqual([
      'multipart/alternative',
      'text/plain',
      'text/html',
    ]);
  });

  it('preserves header order and duplicates for forensic display', async () => {
    const parsed = await parseEmail(sample('phishing/microsoft-account.eml'));
    const received = parsed.headers.filter((h) => h.name === 'Received');
    expect(received).toHaveLength(3);
    expect(received[0]!.value).toContain('by inbox.example.org'); // newest first, folded lines joined
  });

  it('decodes base64 attachments and keeps their bytes for hashing', async () => {
    const parsed = await parseEmail(sample('phishing/fake-invoice.eml'));
    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0]!.filename).toBe('INV-20931.pdf.exe');
    expect(parsed.attachments[0]!.content.subarray(0, 2).toString('latin1')).toBe('MZ');
  });

  it('rejects input that has no RFC 5322 header block', async () => {
    await expect(parseEmail(Buffer.from('just some text\nwith no headers'))).rejects.toMatchObject({
      code: 'not_an_email',
      status: 422,
    });
    await expect(parseEmail(Buffer.from(''))).rejects.toBeInstanceOf(AppError);
  });

  it('survives malformed MIME, broken encodings and unknown charsets', async () => {
    const parsed = await parseEmail(fixture('malformed-mime.eml'));
    expect(parsed.metadata.subject).toBe('Broken multipart');
    expect(parsed.body.text).toContain('verify your account');
    expect(parsed.warnings.some((w) => w.includes('missing its closing boundary'))).toBe(true);
  });

  it('bounds deeply nested MIME structures', async () => {
    const parsed = await parseEmail(fixture('deep-nesting.eml'));
    expect(parsed.warnings.some((w) => w.includes('nesting deeper'))).toBe(true);
    expect(parsed.mimeStructure.length).toBeLessThan(20);
  });

  it('handles CRLF line endings in MIME boundaries', async () => {
    const crlf = Buffer.from(
      sample('legitimate/legitimate-invoice.eml').toString('utf8').replace(/\r?\n/g, '\r\n'),
    );
    const parsed = await parseEmail(crlf);
    expect(parsed.mimeStructure.map((p) => p.contentType)).toEqual([
      'multipart/alternative',
      'text/plain',
      'text/html',
    ]);
    expect(parsed.warnings).toEqual([]);
  });

  it('accepts header-only input for raw header analysis', async () => {
    const parsed = await parseEmail(
      Buffer.from('From: a@example.com\nTo: b@example.org\nSubject: headers only\n'),
    );
    expect(parsed.metadata.subject).toBe('headers only');
    expect(parsed.body.textSource).toBe('none');
  });
});

describe('HTML sanitisation', () => {
  it('removes scripts, event handlers, frames, remote images and live links', async () => {
    const parsed = await parseEmail(fixture('xss-html.eml'));
    const html = parsed.body.sanitizedHtml ?? '';
    expect(html).not.toMatch(/<script|onerror|onload|<iframe|<img|<svg|url\(/i);
    // javascript: survives only as inert attribute text for the analyst to inspect.
    expect(html.replace(/(?:data-href|title)="[^"]*"/g, '')).not.toMatch(/javascript:/i);
    expect(html).not.toMatch(/\shref=/i);
    expect(html).toContain('data-href="javascript:alert(document.cookie)"'); // kept inert for inspection
    expect(parsed.htmlInspection?.scriptCount).toBe(2);
    expect(parsed.htmlInspection?.iframeCount).toBe(1);
  });
});
