/**
 * COPY-SOURCE: ~/Projects/permission-protocol-app/src/lib/permission-protocol-v1/signing/canonicalize.ts
 * CONTRACT: Keep the implementation below byte-identical to the source file body to preserve signing behavior.
 */

/**
 * Receipt Canonicalization
 * 
 * JCS (JSON Canonicalization Scheme) style deterministic serialization.
 * Ensures identical receipts produce identical signatures.
 *
 * CONTRACT: The output bytes are the signing truth; any change is a breaking change.
 */

import { createHash } from 'crypto';

export const CANONICALIZATION_VERSION = 'jcs_v1';

/**
 * Fields included in signature (in canonical order).
 * Excludes: signatureValue, updatedAt, redeemedAt, redeemedRunId, redeemedBy
 */
const SIGNED_FIELDS = [
  'id',
  'companyId',
  'idemKey',
  'agentId',
  'runId',
  'requestJson',
  'inputHash',
  'status',
  'riskTier',
  'policyVersion',
  'reasonCodes',
  'summary',
  'receiptVersion',
  'canonicalization',
  'signatureAlg',
  'signatureKeyId',
  'expiresAt',
  'createdAt',
] as const;

/**
 * Recursively sort object keys for deterministic JSON.
 */
function sortKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sortKeys);
  }
  
  // Preserve "__proto__" as signed data instead of invoking Object.prototype's setter.
  const sorted: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  
  for (const key of keys) {
    sorted[key] = sortKeys((obj as Record<string, unknown>)[key]);
  }
  
  return sorted;
}

/**
 * Serialize date to ISO 8601 string.
 */
function serializeValue(value: unknown): unknown {
  if (value instanceof Date) {
    return value.toISOString();
  }
  return value;
}

/**
 * Extract and canonicalize receipt fields for signing.
 */
export function canonicalizeReceipt(receipt: Record<string, unknown>): string {
  const canonical: Record<string, unknown> = {};
  
  for (const field of SIGNED_FIELDS) {
    const value = receipt[field];
    if (value !== undefined && value !== null) {
      canonical[field] = serializeValue(value);
    }
  }
  
  // Sort keys and stringify deterministically
  const sorted = sortKeys(canonical);
  return JSON.stringify(sorted);
}

export function canonicalizeReceiptBytes(receipt: Record<string, unknown>): Buffer {
  return Buffer.from(canonicalizeReceipt(receipt), 'utf8');
}

/**
 * SHA-256 hash of canonical receipt (for signing).
 */
export function hashCanonical(canonical: string): Buffer {
  return createHash('sha256').update(canonical, 'utf8').digest();
}

/**
 * Generate deterministic receipt hash for scope-based lookup.
 * Used when receipt doesn't exist yet to create idemKey.
 */
export function generateScopeHash(scope: {
  repo?: string;
  env?: string;
  workflow?: string;
  ref?: string;
  commit?: string;
  artifact_digest?: string;
  agentId?: string;
  capability?: string;
}): string {
  const canonical = JSON.stringify(sortKeys(scope));
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}
