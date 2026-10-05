import { randomBytes } from 'node:crypto';

/** Sortable, URL-safe identifier: base36 timestamp + random suffix. */
export function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}${randomBytes(6).toString('hex')}`;
}
