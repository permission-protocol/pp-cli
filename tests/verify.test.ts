import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verify.js';
import { canonicalizeReceipt, canonicalizeReceiptBytes } from '../src/canonicalize.js';

async function loadJson(name: string): Promise<unknown> {
  const path = resolve(process.cwd(), 'tests/fixtures', name);
  return JSON.parse(await readFile(path, 'utf8'));
}

const keyFile = resolve(process.cwd(), 'tests/fixtures/public-key.pem');

describe('verifyReceipt', () => {
  it('verifies a valid receipt', async () => {
    const receipt = await loadJson('valid.json');
    const result = await verifyReceipt(receipt, { keyFile, noNetwork: true });
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.receiptId).toBe('rcpt_valid_001');
    }
  });

  it('returns expired for expired receipt', async () => {
    const receipt = await loadJson('expired.json');
    const result = await verifyReceipt(receipt, { keyFile, noNetwork: true });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(2);
      expect(result.errorCode).toBe('RECEIPT_EXPIRED_OR_REVOKED');
    }
  });

  it('returns malformed for malformed receipt', async () => {
    const receipt = await loadJson('malformed.json');
    const result = await verifyReceipt(receipt, { keyFile, noNetwork: true });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(3);
      expect(result.errorCode).toBe('MALFORMED_RECEIPT');
    }
  });

  it('canonicalize preserves nested __proto__ keys inside signed fields', () => {
    // Forge a requestJson whose value contains a nested __proto__ own
    // key. After the receipt is signed, mutate that value and confirm
    // the canonical signing bytes change. If the canonicalizer routed
    // __proto__ through Object.prototype.__proto__ the value change
    // would be silently dropped and the bytes would not change.
    const inner: Record<string, unknown> = {};
    Object.defineProperty(inner, '__proto__', {
      value: { evil: 'first' },
      writable: true,
      enumerable: true,
      configurable: true,
    });
    const base = {
      id: 'rcpt_proto_001',
      requestJson: inner,
    } as unknown as Record<string, unknown>;
    const originalBytes = canonicalizeReceiptBytes(base);

    // Mutate the nested __proto__ value. With the old sortKeys
    // implementation, this would either silently no-op or rewrite the
    // prototype chain instead of changing the own key. With the fix
    // the canonical bytes must change.
    (base.requestJson as unknown as { __proto__: { evil: string } }).__proto__.evil = 'second';
    const mutatedBytes = canonicalizeReceiptBytes(base);

    expect(mutatedBytes.equals(originalBytes)).toBe(false);
  });

  it('returns signature invalid for wrong key id pin', async () => {
    const receipt = await loadJson('wrong-key.json');
    const result = await verifyReceipt(receipt, { keyFile, keyId: 'pp-test-2026-q2', noNetwork: true });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(4);
      expect(result.errorCode).toBe('KEY_RESOLUTION_FAILED');
    }
  });

  it('returns signature invalid for tampered receipt', async () => {
    const receipt = await loadJson('tampered.json');
    const result = await verifyReceipt(receipt, { keyFile, noNetwork: true });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(1);
      expect(result.errorCode).toBe('SIGNATURE_INVALID');
    }
  });
});
