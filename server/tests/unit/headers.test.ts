import { describe, expect, it } from 'vitest';
import {
  parseAuthenticationResults,
  summariseAuthentication,
} from '../../src/services/analyzers/authentication.js';
import { analyseReceivedChain } from '../../src/services/analyzers/receivedChain.js';
import { parseRawHeaders, splitHeaderBlock } from '../../src/services/parser/headers.js';

describe('raw header parsing', () => {
  it('unfolds continuation lines and keeps duplicates in order', () => {
    const headers = parseRawHeaders(
      'Received: from a\n\tby b; Mon, 1 Jan 2026 10:00:00 +0000\nReceived: from c by d\nSubject: hi',
    );
    expect(headers).toEqual([
      { name: 'Received', value: 'from a by b; Mon, 1 Jan 2026 10:00:00 +0000' },
      { name: 'Received', value: 'from c by d' },
      { name: 'Subject', value: 'hi' },
    ]);
  });

  it('recognises mbox separators but rejects non-email text', () => {
    expect(
      splitHeaderBlock('From someone@x Mon Jan 1 00:00:00 2026\nFrom: a@b.c\n\nbody'),
    ).not.toBeNull();
    expect(splitHeaderBlock('Hello there\n\nbody')).toBeNull();
  });
});

describe('Received chain analysis', () => {
  it('orders hops chronologically and flags backwards timestamps and missing rDNS', () => {
    const hops = analyseReceivedChain([
      'from mx.example.org by inbox.example.org; Mon, 14 Sep 2026 09:00:00 +0000',
      'from unknown (unknown [203.0.113.77]) by mx.example.org; Mon, 14 Sep 2026 09:30:00 +0000',
    ]);
    expect(hops[0]!.fromIp).toBe('203.0.113.77');
    expect(hops[0]!.flags).toContain('no reverse DNS for sending IP');
    expect(hops[1]!.delaySeconds).toBe(-1800);
    expect(hops[1]!.flags).toContain('timestamp earlier than previous hop');
  });

  it('does not flag private origin addresses as missing rDNS', () => {
    const [hop] = analyseReceivedChain([
      'from localhost (unknown [10.0.0.4]) by relay.example.org; Mon, 14 Sep 2026 09:00:00 +0000',
    ]);
    expect(hop!.flags).not.toContain('no reverse DNS for sending IP');
  });
});

describe('Authentication-Results parsing', () => {
  it('parses RFC 8601 results and ignores comments', () => {
    const results = parseAuthenticationResults(
      'mx.example.org; spf=fail (not permitted) smtp.mailfrom=bad.example; dkim=none (message not signed); dmarc=fail (p=reject) header.from=paypal.com',
    );
    expect(results.spf).toEqual({ result: 'fail', props: { 'smtp.mailfrom': 'bad.example' } });
    expect(results.dkim?.result).toBe('none');
    expect(results.dmarc?.props['header.from']).toBe('paypal.com');
  });

  it('handles Exchange Online headers without an authserv-id', () => {
    const results = parseAuthenticationResults(
      'spf=none (sender IP is 57.128.69.202) smtp.mailfrom=dturm.de; dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=appjj.example.fr;compauth=fail reason=001',
    );
    expect(results.spf?.result).toBe('none');
    expect(results.dmarc?.props['header.from']).toBe('appjj.example.fr');
  });

  it('maps results onto the four analyst-facing states without inventing data', () => {
    const summary = summariseAuthentication({
      authResults: [
        'mx; spf=softfail smtp.mailfrom=x.example; dmarc=temperror header.from=x.example',
      ],
      receivedSpf: [],
      dkimSignatures: ['v=1; d=x.example'],
      fromDomain: 'x.example',
    });
    expect(summary.spf.state).toBe('fail');
    expect(summary.spf.result).toBe('softfail');
    expect(summary.dmarc.state).toBe('unknown');
    expect(summary.dkim.state).toBe('unknown'); // signature present but unverified
    const empty = summariseAuthentication({
      authResults: [],
      receivedSpf: [],
      dkimSignatures: [],
      fromDomain: 'x.example',
    });
    expect([empty.spf.state, empty.dkim.state, empty.dmarc.state]).toEqual([
      'not_present',
      'not_present',
      'not_present',
    ]);
  });

  it('trusts only the top-most Authentication-Results header', () => {
    const summary = summariseAuthentication({
      authResults: [
        'recipient.example; dmarc=fail header.from=bank.example',
        'attacker.example; dmarc=pass header.from=bank.example',
      ],
      receivedSpf: [],
      dkimSignatures: [],
      fromDomain: 'bank.example',
    });
    expect(summary.dmarc.state).toBe('fail');
    expect(summary.headerCount).toBe(2);
  });
});
