// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

/** Remove control characters and collapse whitespace for safe single-line display. */
export function cleanLine(value: string, max = 500): string {
  const cleaned = value.replace(CONTROL_CHARACTERS, '').replace(/\s+/g, ' ').trim();
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}

/** Render a URL or domain inert for display ("defanging"), as analysts expect. */
export function defang(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

export function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

export function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}
