/**
 * Characters that render like Latin letters. Derived from the Unicode
 * confusables data (UTS #39) for the scripts seen in IDN phishing.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a',
  в: 'b',
  е: 'e',
  ё: 'e',
  һ: 'h',
  і: 'i',
  ї: 'i',
  ј: 'j',
  к: 'k',
  ӏ: 'l',
  м: 'm',
  н: 'h',
  о: 'o',
  р: 'p',
  ԛ: 'q',
  г: 'r',
  ѕ: 's',
  т: 't',
  ц: 'u',
  ѵ: 'v',
  ԝ: 'w',
  х: 'x',
  у: 'y',
  ԁ: 'd',
  ɡ: 'g',
  ү: 'y',
  ꮪ: 's',
  // Greek
  α: 'a',
  β: 'b',
  ε: 'e',
  η: 'n',
  ι: 'i',
  κ: 'k',
  ν: 'v',
  ο: 'o',
  ρ: 'p',
  τ: 't',
  υ: 'u',
  χ: 'x',
  γ: 'y',
  ω: 'w',
  // Latin look-alikes and dotless forms
  ı: 'i',
  ł: 'l',
  ɩ: 'i',
  ɑ: 'a',
  ƅ: 'b',
  ԃ: 'd',
  ꞵ: 'b',
};

/** Digit and multi-letter substitutions used in typosquats ("paypa1", "rnicrosoft"). */
const LEET: [RegExp, string][] = [
  [/0/g, 'o'],
  [/1/g, 'l'],
  [/3/g, 'e'],
  [/4/g, 'a'],
  [/5/g, 's'],
  [/7/g, 't'],
  [/\$/g, 's'],
  [/rn/g, 'm'],
  [/vv/g, 'w'],
];

export function hasNonAscii(value: string): boolean {
  return /[^\x20-\x7e\t\r\n]/.test(value);
}

export function scriptsIn(value: string): string[] {
  const scripts = new Set<string>();
  for (const char of value) {
    if (/\p{Script=Latin}/u.test(char)) scripts.add('Latin');
    else if (/\p{Script=Cyrillic}/u.test(char)) scripts.add('Cyrillic');
    else if (/\p{Script=Greek}/u.test(char)) scripts.add('Greek');
    else if (/\p{Script=Armenian}/u.test(char)) scripts.add('Armenian');
    else if (/\p{L}/u.test(char)) scripts.add('Other');
  }
  return [...scripts];
}

/** Map visually confusable Unicode characters to Latin equivalents (NFKC first). */
export function unicodeSkeleton(value: string): string {
  return [...value.normalize('NFKC').toLowerCase()]
    .map((char) => CONFUSABLES[char] ?? char)
    .join('');
}

/** Full skeleton: Unicode confusables plus digit/letter-cluster substitutions. */
export function skeleton(value: string): string {
  let out = unicodeSkeleton(value);
  for (const [pattern, replacement] of LEET) out = out.replace(pattern, replacement);
  return out;
}

export function confusableCharacters(value: string): string[] {
  return [...value].filter((char) => CONFUSABLES[char] !== undefined);
}
