/**
 * The name of an unlock passkey as the vault stores it. Shared by the
 * background, which enforces it, and the unlock and options pages, which
 * check a name before a passkey prompt opens. No imports, so the pages take
 * no cryptography with it.
 */

export const MAX_PASSKEY_NAME_LENGTH = 64;

/**
 * A passkey name as stored: trimmed, 1..64 code points, no control
 * characters. Null when the input cannot be one.
 */
export function cleanPasskeyName(name: unknown): string | null {
  if (typeof name !== 'string') return null;
  const trimmed = name.trim();
  const length = Array.from(trimmed).length;
  if (length < 1 || length > MAX_PASSKEY_NAME_LENGTH) return null;
  for (const character of trimmed) {
    const code = character.codePointAt(0)!;
    // C0 and C1 controls, and the line and paragraph separators.
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      return null;
    }
  }
  return trimmed;
}
