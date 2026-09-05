/**
 * Accepts a single secret or a list of active secrets and returns a non-empty list.
 *
 * A list is how rotation works: the sender signs with the first entry, the receiver accepts a
 * signature made with any entry. Keep the outgoing secret first and the retiring one after it
 * while both are live, then drop the old one.
 */
export function normalizeSecrets(secrets: string | string[]): string[] {
  const list = Array.isArray(secrets) ? secrets : [secrets];
  if (list.length === 0 || list.some((s) => typeof s !== 'string' || s.length === 0)) {
    throw new Error('secrets must not be empty');
  }
  return list;
}
