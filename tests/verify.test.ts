import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verify.js';

async function loadJson(name: string): Promise<unknown> {
  const path = resolve(process.cwd(), 'tests/fixtures', name);
  return JSON.parse(await readFile(path, 'utf8'));
}

const keyFile = resolve(process.cwd(), 'tests/fixtures/public-key.pem');
const rawKeyFile = resolve(process.cwd(), 'tests/fixtures/public-key.raw-base64');

describe('verifyReceipt', () => {
  it('verifies a valid receipt', async () => {
    const receipt = await loadJson('valid.json');
    const result = await verifyReceipt(receipt, { keyFile, noNetwork: true });
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.receiptId).toBe('rcpt_valid_001');
    }
  });

  it('verifies a valid receipt with a raw Ed25519 base64 public key', async () => {
    const receipt = await loadJson('valid.json');
    const result = await verifyReceipt(receipt, { keyFile: rawKeyFile, noNetwork: true });
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
