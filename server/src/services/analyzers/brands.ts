/**
 * Brands commonly impersonated in phishing, with the registrable domains they
 * legitimately send from or host on. Lookalike detection compares candidate
 * domains against `keywords` with similarity algorithms, so this list names
 * what to protect - it is not a blocklist of bad domains.
 */
export interface Brand {
  name: string;
  keywords: string[];
  domains: string[];
}

export const BRANDS: Brand[] = [
  {
    name: 'Microsoft',
    keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint'],
    domains: [
      'microsoft.com',
      'live.com',
      'outlook.com',
      'office.com',
      'office365.com',
      'microsoftonline.com',
      'sharepoint.com',
      'onedrive.com',
      'hotmail.com',
      'skype.com',
      'xbox.com',
      'azure.com',
      'windows.net',
      'msn.com',
    ],
  },
  {
    name: 'Google',
    keywords: ['google', 'gmail'],
    domains: [
      'google.com',
      'gmail.com',
      'googlemail.com',
      'youtube.com',
      'google.co.in',
      'googleusercontent.com',
      'gstatic.com',
    ],
  },
  {
    name: 'Apple',
    keywords: ['apple', 'icloud', 'itunes'],
    domains: ['apple.com', 'icloud.com', 'me.com', 'itunes.com'],
  },
  {
    name: 'Amazon',
    keywords: ['amazon'],
    domains: [
      'amazon.com',
      'amazon.in',
      'amazon.co.uk',
      'amazon.de',
      'amazonaws.com',
      'amazonses.com',
    ],
  },
  {
    name: 'PayPal',
    keywords: ['paypal'],
    domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
  },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com'] },
  {
    name: 'Meta',
    keywords: ['facebook', 'instagram', 'whatsapp'],
    domains: [
      'facebook.com',
      'fb.com',
      'meta.com',
      'instagram.com',
      'whatsapp.com',
      'facebookmail.com',
    ],
  },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com', 'licdn.com'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.de', 'dhl.co.in'] },
  { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
  { name: 'UPS', keywords: ['ups'], domains: ['ups.com'] },
  { name: 'USPS', keywords: ['usps'], domains: ['usps.com'] },
  { name: 'Adobe', keywords: ['adobe'], domains: ['adobe.com', 'adobesign.com'] },
  { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com', 'dropboxmail.com'] },
  { name: 'Chase', keywords: ['chase'], domains: ['chase.com', 'jpmorgan.com'] },
  { name: 'Wells Fargo', keywords: ['wellsfargo'], domains: ['wellsfargo.com'] },
  {
    name: 'Bank of America',
    keywords: ['bankofamerica'],
    domains: ['bankofamerica.com', 'bofa.com'],
  },
  { name: 'HDFC Bank', keywords: ['hdfc', 'hdfcbank'], domains: ['hdfcbank.com', 'hdfcbank.net'] },
  { name: 'ICICI Bank', keywords: ['icici', 'icicibank'], domains: ['icicibank.com'] },
  {
    name: 'State Bank of India',
    keywords: ['onlinesbi', 'sbicard'],
    domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbicard.com'],
  },
  { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'Binance', keywords: ['binance'], domains: ['binance.com'] },
  { name: 'MetaMask', keywords: ['metamask'], domains: ['metamask.io'] },
  {
    name: 'Steam',
    keywords: ['steampowered', 'steamcommunity'],
    domains: ['steampowered.com', 'steamcommunity.com'],
  },
  { name: 'GitHub', keywords: ['github'], domains: ['github.com', 'githubusercontent.com'] },
  { name: 'Zoom', keywords: ['zoom'], domains: ['zoom.us', 'zoom.com'] },
  { name: 'Slack', keywords: ['slack'], domains: ['slack.com'] },
  { name: 'Spotify', keywords: ['spotify'], domains: ['spotify.com'] },
  {
    name: 'Income Tax Department (India)',
    keywords: ['incometax', 'incometaxindia'],
    domains: ['incometax.gov.in', 'incometaxindia.gov.in'],
  },
  { name: 'IRS', keywords: ['irs'], domains: ['irs.gov'] },
];

const OFFICIAL = new Map<string, Brand>();
for (const brand of BRANDS) for (const domain of brand.domains) OFFICIAL.set(domain, brand);

export function brandForOfficialDomain(registrableDomain: string): Brand | undefined {
  return OFFICIAL.get(registrableDomain.toLowerCase());
}

/** Brand names as they appear in prose and display names. */
export const BRAND_MENTION_PATTERNS: { brand: Brand; pattern: RegExp }[] = BRANDS.map((brand) => {
  const names = new Set([brand.name, ...brand.keywords.filter((k) => k.length >= 4)]);
  const alternation = [...names]
    .map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s*'))
    .join('|');
  return { brand, pattern: new RegExp(`\\b(?:${alternation})\\b`, 'i') };
});
