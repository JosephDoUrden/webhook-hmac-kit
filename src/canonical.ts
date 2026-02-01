export function buildCanonicalString(
  version: string,
  timestamp: number,
  nonce: string,
  payload: string,
): string {
  return `${version}:${timestamp}:${nonce}:${payload}`;
}
