import { domainOfAddress, orgDomain } from '../../services/parser/headers.js';
import type { Detector } from '../types.js';

export const returnPathMismatchDetector: Detector = {
  id: 'header.return_path_mismatch',
  category: 'sender',
  description: 'Envelope sender (Return-Path) from a different organisation',
  run({ metadata, sender, authentication }) {
    if (!metadata.returnPath || !sender.orgDomain) return [];
    const returnDomain = domainOfAddress(metadata.returnPath);
    if (!returnDomain || orgDomain(returnDomain) === sender.orgDomain) return [];
    // Legitimate ESPs (bounce handling) commonly use their own Return-Path;
    // when DMARC passes via aligned DKIM that is expected and only informational.
    const authenticated = authentication.dmarc.state === 'pass';
    return [
      {
        severity: authenticated ? 'info' : 'low',
        confidence: authenticated ? 0.5 : 0.7,
        title: 'Return-Path domain differs from From domain',
        description: `Bounces go to ${metadata.returnPath} while the visible sender is ${sender.address}.`,
        whyItMatters: authenticated
          ? 'Common with email service providers that handle bounces; DMARC passed, so the From domain is still authenticated.'
          : 'Without DMARC alignment, a different envelope sender suggests the visible From address was set independently of the real sending infrastructure.',
        evidence: [
          { label: 'From', value: sender.address ?? '' },
          { label: 'Return-Path', value: metadata.returnPath },
        ],
        recommendation: 'Weigh together with the authentication results.',
        method: 'Compared organisational domains of the Return-Path and From headers.',
        scoreGroup: 'sender',
      },
    ];
  },
};
