import type { Detector } from '../types.js';

export const hiddenContentDetector: Detector = {
  id: 'content.hidden_text',
  category: 'content',
  description: 'Text hidden from the reader in the HTML body',
  run({ message }) {
    const hidden = message.htmlInspection?.hiddenText ?? [];
    const scripts = message.htmlInspection?.scriptCount ?? 0;
    if (!hidden.length && !scripts) return [];
    return [
      {
        severity: scripts ? 'high' : 'medium',
        confidence: 0.8,
        title: scripts ? 'Script content in HTML email' : 'Hidden text in HTML body',
        description: scripts
          ? `The HTML contains ${scripts} script element(s)${hidden.length ? ` and ${hidden.length} hidden text block(s)` : ''}.`
          : `${hidden.length} block(s) of text are styled to be invisible to the reader.`,
        whyItMatters:
          'Invisible text is used to feed benign-looking words to spam filters (filter evasion). Mail clients do not run scripts, so their presence signals a payload aimed at a browser.',
        evidence: [
          ...hidden
            .slice(0, 4)
            .map((text) => ({ label: 'Hidden text', value: text.slice(0, 200) })),
          ...(scripts ? [{ label: 'Script tags', value: String(scripts) }] : []),
        ],
        recommendation:
          'Treat the visible message with suspicion; legitimate senders have no need to hide text.',
        method:
          'Walked the HTML DOM for elements styled display:none, visibility:hidden, zero font size or opacity, and for script tags.',
        scoreGroup: 'content_hidden',
      },
    ];
  },
};
