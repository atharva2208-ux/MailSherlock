import { createHash } from 'node:crypto';
import { simpleParser, type AddressObject, type ParsedMail } from 'mailparser';
import type { EmailBody, EmailMetadata, Mailbox, MimePart } from '../../models/analysis.js';
import { unprocessable } from '../../utils/errors.js';
import { cleanLine } from '../../utils/text.js';
import {
  firstHeader,
  headerValues,
  parseRawHeaders,
  returnPathAddress,
  splitHeaderBlock,
  toMailbox,
  type RawHeader,
} from './headers.js';
import { inspectHtml, sanitizeForDisplay, type HtmlInspection } from './html.js';
import { describeMimeStructure } from './mime.js';

export const MAX_BODY_TEXT = 100_000;

export interface ParsedAttachment {
  filename: string;
  contentType: string;
  content: Buffer;
  size: number;
}

export interface ParsedMessage {
  raw: string;
  sizeBytes: number;
  sha256: string;
  headers: RawHeader[];
  metadata: EmailMetadata;
  body: EmailBody;
  html?: string;
  htmlInspection?: HtmlInspection;
  attachments: ParsedAttachment[];
  mimeStructure: MimePart[];
  warnings: string[];
}

function mailboxes(value: AddressObject | AddressObject[] | undefined): Mailbox[] {
  if (!value) return [];
  const list = Array.isArray(value) ? value : [value];
  const out: Mailbox[] = [];
  for (const group of list) {
    for (const entry of group.value) {
      const members = entry.group ?? [entry];
      for (const member of members) {
        const mailbox = toMailbox(member.name, member.address);
        if (mailbox) out.push(mailbox);
      }
    }
  }
  return out.slice(0, 200);
}

/**
 * Parse a raw RFC 5322 message. Every uploaded message is treated as hostile:
 * the parser never executes or fetches anything, and structural problems are
 * reported as warnings instead of aborting the analysis wherever possible.
 */
export async function parseEmail(input: Buffer): Promise<ParsedMessage> {
  const raw = input.toString('utf8').replace(/^\uFEFF/, '');
  const split = splitHeaderBlock(raw);
  if (!split) {
    throw unprocessable(
      'not_an_email',
      'The input does not start with an RFC 5322 header block (lines such as "From: ..." and "Subject: ..."), so it cannot be analysed as an email.',
    );
  }

  const headers = parseRawHeaders(split.headerBlock);
  const warnings: string[] = [];
  let mail: ParsedMail;
  try {
    mail = await simpleParser(input, {
      skipImageLinks: true,
      skipTextToHtml: true,
      skipTextLinks: true,
      maxHtmlLengthToParse: 5_000_000,
    });
  } catch (error) {
    throw unprocessable(
      'mime_parse_failed',
      `The email could not be parsed because its MIME structure is malformed (${error instanceof Error ? error.message : 'unknown error'}).`,
    );
  }

  const { parts: mimeStructure, warnings: mimeWarnings } = describeMimeStructure(raw);
  warnings.push(...mimeWarnings);

  const from = mailboxes(mail.from)[0];
  const replyTo = mailboxes(mail.replyTo);
  const metadata: EmailMetadata = {
    from,
    replyTo: replyTo.length ? replyTo : undefined,
    returnPath: returnPathAddress(firstHeader(headers, 'return-path')),
    to: mailboxes(mail.to),
    cc: mailboxes(mail.cc),
    bcc: mailboxes(mail.bcc),
    subject: cleanLine(mail.subject ?? '', 998),
    date: mail.date && !Number.isNaN(mail.date.getTime()) ? mail.date.toISOString() : undefined,
    messageId: firstHeader(headers, 'message-id'),
    userAgent: firstHeader(headers, 'user-agent'),
    xMailer: firstHeader(headers, 'x-mailer'),
    headers: headers.map((h) => ({ name: h.name, value: h.value.slice(0, 4000) })),
  };
  if (!firstHeader(headers, 'from')) warnings.push('Message has no From header');
  if (firstHeader(headers, 'date') && !metadata.date)
    warnings.push('Date header could not be parsed');
  if (headerValues(headers, 'from').length > 1)
    warnings.push('Message contains more than one From header');

  const html = typeof mail.html === 'string' && mail.html.trim() ? mail.html : undefined;
  const hasPlainPart = mimeStructure.some((p) => p.contentType === 'text/plain' && !p.filename);
  const text = (mail.text ?? '').replace(/\r\n/g, '\n');
  const body: EmailBody = {
    text: text.slice(0, MAX_BODY_TEXT),
    textSource: !text.trim() ? 'none' : hasPlainPart || !html ? 'plain' : 'html',
    sanitizedHtml: html ? sanitizeForDisplay(html) : undefined,
    hasHtml: Boolean(html),
    truncated: text.length > MAX_BODY_TEXT,
  };

  const attachments: ParsedAttachment[] = mail.attachments.slice(0, 100).map((a) => ({
    filename: a.filename ?? '',
    contentType: (a.contentType || 'application/octet-stream').toLowerCase(),
    content: a.content,
    size: a.size ?? a.content.length,
  }));
  if (mail.attachments.length > 100) warnings.push('Only the first 100 attachments were analysed');

  return {
    raw,
    sizeBytes: input.length,
    sha256: createHash('sha256').update(input).digest('hex'),
    headers,
    metadata,
    body,
    html,
    htmlInspection: html ? inspectHtml(html) : undefined,
    attachments,
    mimeStructure,
    warnings,
  };
}
