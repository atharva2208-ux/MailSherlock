import { Parser } from 'htmlparser2';
import sanitizeHtml from 'sanitize-html';

export interface HtmlAnchor {
  href: string;
  text: string;
}

export interface HtmlForm {
  action: string;
  method: string;
  hasPasswordField: boolean;
  inputNames: string[];
}

export interface HtmlInspection {
  anchors: HtmlAnchor[];
  forms: HtmlForm[];
  images: string[];
  hiddenText: string[];
  scriptCount: number;
  iframeCount: number;
  metaRefresh?: string;
}

const HIDDEN_STYLE =
  /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\b|opacity\s*:\s*0(?:\.0+)?\b|max-height\s*:\s*0/i;
const VOID_ELEMENTS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'source',
  'track',
  'wbr',
]);
const MAX_ITEMS = 500;

/**
 * Walk the HTML once, collecting the structures phishing relies on: link
 * targets vs. their visible text, credential forms, hidden text and remote
 * resources. Nothing is fetched or executed.
 */
export function inspectHtml(html: string): HtmlInspection {
  const result: HtmlInspection = {
    anchors: [],
    forms: [],
    images: [],
    hiddenText: [],
    scriptCount: 0,
    iframeCount: 0,
  };
  const stack: { tag: string; hidden: boolean }[] = [];
  let anchor: { href: string; text: string[] } | null = null;
  let form: HtmlForm | null = null;
  let hiddenBuffer: string[] = [];

  const hiddenDepth = () => stack.some((entry) => entry.hidden);

  const parser = new Parser(
    {
      onopentag(name, attrs) {
        const hidden =
          HIDDEN_STYLE.test(attrs.style ?? '') ||
          'hidden' in attrs ||
          attrs['aria-hidden'] === 'true';
        if (name === 'a' && attrs.href && result.anchors.length < MAX_ITEMS)
          anchor = { href: attrs.href.trim(), text: [] };
        if (name === 'form')
          form = {
            action: (attrs.action ?? '').trim(),
            method: (attrs.method ?? 'get').toLowerCase(),
            hasPasswordField: false,
            inputNames: [],
          };
        if (name === 'input' && form) {
          if ((attrs.type ?? '').toLowerCase() === 'password') form.hasPasswordField = true;
          if (attrs.name) form.inputNames.push(attrs.name.slice(0, 60));
        }
        if (name === 'img' && attrs.src && result.images.length < MAX_ITEMS)
          result.images.push(attrs.src.trim());
        if (name === 'script') result.scriptCount += 1;
        if (name === 'iframe') result.iframeCount += 1;
        if (name === 'meta' && /refresh/i.test(attrs['http-equiv'] ?? ''))
          result.metaRefresh = attrs.content;
        if (!VOID_ELEMENTS.has(name)) stack.push({ tag: name, hidden });
      },
      ontext(text) {
        if (anchor) anchor.text.push(text);
        if (hiddenDepth() && text.trim()) hiddenBuffer.push(text.trim());
      },
      onclosetag(name) {
        if (name === 'a' && anchor) {
          result.anchors.push({
            href: anchor.href,
            text: anchor.text.join(' ').replace(/\s+/g, ' ').trim().slice(0, 300),
          });
          anchor = null;
        }
        if (name === 'form' && form) {
          if (result.forms.length < 50) result.forms.push(form);
          form = null;
        }
        if (VOID_ELEMENTS.has(name)) return;
        const index = stack.map((s) => s.tag).lastIndexOf(name);
        if (index >= 0) {
          const closingHidden = stack[index]!.hidden;
          stack.length = index;
          if (closingHidden && !hiddenDepth() && hiddenBuffer.length) {
            const text = hiddenBuffer.join(' ').slice(0, 300);
            if (text.length > 2 && result.hiddenText.length < 50) result.hiddenText.push(text);
            hiddenBuffer = [];
          }
        }
      },
    },
    { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true },
  );
  parser.write(html);
  parser.end();
  return result;
}

/**
 * Produce HTML that is safe to display in a sandboxed, script-less iframe.
 * Links are neutralised (href removed, original kept as a data attribute for
 * hover inspection) and remote images are dropped so opening an email in
 * MailSherlock never contacts the attacker's infrastructure.
 */
export function sanitizeForDisplay(html: string): string {
  return sanitizeHtml(html, {
    allowedTags: [
      'p',
      'br',
      'div',
      'span',
      'b',
      'strong',
      'i',
      'em',
      'u',
      's',
      'small',
      'big',
      'sub',
      'sup',
      'h1',
      'h2',
      'h3',
      'h4',
      'h5',
      'h6',
      'ul',
      'ol',
      'li',
      'blockquote',
      'pre',
      'code',
      'hr',
      'table',
      'thead',
      'tbody',
      'tfoot',
      'tr',
      'td',
      'th',
      'caption',
      'center',
      'font',
      'a',
    ],
    allowedAttributes: {
      a: ['data-href', 'title'],
      td: ['colspan', 'rowspan', 'align'],
      th: ['colspan', 'rowspan', 'align'],
      '*': ['style'],
    },
    allowedStyles: {
      '*': {
        color: [/^#(?:[0-9a-f]{3}){1,2}$/i, /^rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)$/i, /^[a-z]+$/i],
        'font-weight': [/^(?:bold|normal|\d{3})$/],
        'font-style': [/^(?:italic|normal)$/],
        'text-align': [/^(?:left|right|center|justify)$/],
        'text-decoration': [/^[a-z ]+$/],
        // Kept so hidden-text tricks remain visible to the analyst as hidden.
        display: [/^none$/],
      },
    },
    allowedSchemes: [],
    transformTags: {
      a: (_tag, attribs) => ({
        tagName: 'a',
        attribs: {
          'data-href': (attribs.href ?? '').slice(0, 2048),
          title: (attribs.href ?? '').slice(0, 2048),
        },
      }),
    },
    exclusiveFilter: (frame) => frame.tag === 'title',
  });
}
