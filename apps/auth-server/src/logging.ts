const secretFields = new Set([
  'password',
  'otp',
  'code',
  'token',
  'cookie',
  'authorization',
  'secret',
  'key',
  'sessionkey',
  'privatekey',
  'dataencryptionkey',
  'databaseurl',
  'redisurl',
]);
export const safeRequest = (request: { id?: string; method?: string }) => ({
  id: request.id,
  method: request.method,
});
export const safeResponse = (response: { statusCode?: number }) => ({
  statusCode: response.statusCode,
});
export const safeError = () => ({ type: 'Error', message: 'Request failed', stack: '[REDACTED]' });
// Recursive and case-insensitive, including array members. No URL/header/body
// serialization in automatic request logs and no raw exception text or stack.
export function redact(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value instanceof Error) return safeError();
  if (value instanceof Uint8Array) return '[REDACTED]';
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redact(item, seen));
  const output: Record<string, unknown> = {};
  for (const [name, item] of Object.entries(value)) {
    if (secretFields.has(name.toLowerCase())) output[name] = '[REDACTED]';
    else if (name === 'req') output[name] = safeRequest(item ?? {});
    else if (name === 'res') output[name] = safeResponse(item ?? {});
    else if (name === 'err') output[name] = safeError();
    else output[name] = redact(item, seen);
  }
  return output;
}
