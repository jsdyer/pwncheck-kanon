// Passwords and full hashes are deliberately never returned by the checker.
export const RANGE_ORIGIN = 'https://api.pwnedpasswords.com';

export function validateConfig(value) {
  for (const [key, min, max] of [['timeoutMs', 1000, 60000], ['maxPasswordBytes', 1, 65536], ['maxResponseBytes', 40000, 2097152]]) {
    if (!Number.isSafeInteger(value?.[key]) || value[key] < min || value[key] > max) throw new Error('The checker configuration is invalid.');
  }
  return Object.freeze({ timeoutMs: value.timeoutMs, maxPasswordBytes: value.maxPasswordBytes, maxResponseBytes: value.maxResponseBytes });
}

export async function hashParts(password, maxBytes, cryptoProvider = globalThis.crypto) {
  if (typeof password !== 'string' || password.length === 0) throw new Error('Enter a password to check.');
  const bytes = new TextEncoder().encode(password); // Preserve exact input; no trimming or normalization.
  if (bytes.length > maxBytes) throw new Error(`Use a password no longer than ${maxBytes.toLocaleString()} UTF-8 bytes.`);
  if (!cryptoProvider?.subtle) throw new Error('This browser needs a secure HTTPS connection and Web Crypto support.');
  const digest = new Uint8Array(await cryptoProvider.subtle.digest('SHA-1', bytes));
  bytes.fill(0);
  const hash = [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  digest.fill(0);
  return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

export function rangeRequest(prefix, signal) {
  if (!/^[A-F0-9]{5}$/.test(prefix)) throw new Error('The request must contain exactly five hash characters.');
  return [ `${RANGE_ORIGIN}/range/${prefix}`, {
    method: 'GET', headers: { 'Add-Padding': 'true', Accept: 'text/plain' },
    credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', redirect: 'error', signal,
  } ];
}

export function matchRange(text, suffix) {
  if (!/^[A-F0-9]{35}$/.test(suffix)) throw new Error('The local comparison is invalid.');
  if (typeof text !== 'string' || !text.trim()) throw new Error('The provider returned an empty response. Try again later.');
  let count = 0;
  let records = 0;
  const seen = new Set();
  for (const line of text.trim().split(/\r?\n/)) {
    const match = /^([A-Fa-f0-9]{35}):([0-9]+)$/.exec(line);
    if (!match) throw new Error('The provider returned an unexpected response. No result is available.');
    const value = Number(match[2]);
    const candidate = match[1].toUpperCase();
    if (!Number.isSafeInteger(value) || seen.has(candidate)) throw new Error('The provider returned an unexpected response. No result is available.');
    seen.add(candidate);
    if (value === 0) continue; // Synthetic padding entries are never matches.
    records++;
    if (candidate === suffix) count = value;
  }
  if (records === 0) throw new Error('The provider returned no usable records. Try again later.');
  return { found: count > 0, count };
}

async function readBounded(response, limit) {
  const size = Number(response.headers?.get('content-length'));
  if (size > limit) throw new Error('The provider response exceeded the size limit. No result is available.');
  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text();
    if (new TextEncoder().encode(text).length > limit) throw new Error('The provider response exceeded the size limit. No result is available.');
    return text;
  }
  const decoder = new TextDecoder();
  let length = 0;
  let text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) { await reader.cancel(); throw new Error('The provider response exceeded the size limit. No result is available.'); }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally { reader.releaseLock(); }
}

export async function checkPassword(password, config, { signal, fetcher = globalThis.fetch, cryptoProvider = globalThis.crypto } = {}) {
  const settings = validateConfig(config);
  const { prefix, suffix } = await hashParts(password, settings.maxPasswordBytes, cryptoProvider);
  signal?.throwIfAborted(); // Editing/resetting while hashing must prevent a later request.
  const response = await fetcher(...rangeRequest(prefix, signal));
  if (!response.ok) throw new Error(response.status === 429 ? 'The provider is asking for a pause. Please try again later.' : 'The provider could not complete the check. Please try again later.');
  const text = await readBounded(response, settings.maxResponseBytes);
  signal?.throwIfAborted();
  return matchRange(text, suffix);
}
