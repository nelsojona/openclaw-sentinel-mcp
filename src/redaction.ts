/**
 * Argument redaction for audit logging
 * Sensitive fields are replaced with [REDACTED] to prevent credential leakage
 */

/**
 * Sensitive field patterns (case-insensitive)
 */
const SENSITIVE_PATTERNS = [
  /password/i,
  /passwd/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /access[_-]?key/i,
  /private[_-]?key/i,
  /credential/i,
  /auth/i,
  /bearer/i,
  /jwt/i,
];

/**
 * Check if a field name is sensitive
 */
function isSensitiveField(fieldName: string): boolean {
  return SENSITIVE_PATTERNS.some((pattern) => pattern.test(fieldName));
}

/**
 * Redact sensitive fields in arguments object
 *
 * Preserves structure for forensics but hides sensitive values.
 * Handles nested objects and arrays recursively.
 *
 * @param args - Arguments object to redact
 * @returns Redacted copy of arguments
 */
export function redactSensitiveFields(args: Record<string, unknown>): Record<string, unknown> {
  const redacted: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(args)) {
    if (isSensitiveField(key)) {
      // Redact sensitive field
      redacted[key] = '[REDACTED]';
    } else if (value === null || value === undefined) {
      // Preserve null/undefined
      redacted[key] = value;
    } else if (Array.isArray(value)) {
      // Recurse into arrays
      redacted[key] = value.map((item) => {
        if (typeof item === 'object' && item !== null) {
          return redactSensitiveFields(item as Record<string, unknown>);
        }
        return item;
      });
    } else if (typeof value === 'object') {
      // Recurse into nested objects
      redacted[key] = redactSensitiveFields(value as Record<string, unknown>);
    } else {
      // Preserve primitive values
      redacted[key] = value;
    }
  }

  return redacted;
}

/**
 * Redact and serialize arguments for audit log
 *
 * @param args - Arguments to redact and serialize
 * @returns JSON string with redacted sensitive fields
 */
export function redactAndSerialize(args: Record<string, unknown>): string {
  const redacted = redactSensitiveFields(args);
  return JSON.stringify(redacted);
}
