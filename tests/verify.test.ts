import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verify.js';

async function loadJson(name: string): Promise<unknown> {
  const path = resolve(process.cwd(), 'tests/fixtures', name);
  return JSON.parse(await readFile(path, 'utf8'));
}

const keyFile = resolve(process.cwd(), 'tests/fixtures/public-key.pem');
const remoteKeyFile = resolve(process.cwd(), 'tests/fixtures/public-key.base64');

async function remoteKeyUrl(status?: unknown): Promise<string> {
  const publicKey = (await readFile(remoteKeyFile, 'utf8')).trim();
  const payload = {
    keyId: 'pp-test-2026-q2',
    algorithm: 'ed25519',
    publicKey,
    ...(status === undefined ? {} : { status }),
  };
  return `data:application/json,${encodeURIComponent(JSON.stringify(payload))}`;
}

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

  it('returns signature invalid for wrong key id pin', async () => {
    const receipt = await loadJson('wrong-key.json');
    const result = await verifyReceipt(receipt, { keyFile, keyId: 'pp-test-2026-q2', noNetwork: true });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(4);
      expect(result.errorCode).toBe('KEY_RESOLUTION_FAILED');
    }
  });

  it('verifies a receipt with a remotely resolved rotated key', async () => {
    const receipt = await loadJson('valid.json');
    const result = await verifyReceipt(receipt, { keyUrl: await remoteKeyUrl('rotated') });
    expect(result.verified).toBe(true);
  });

  it('rejects a remotely resolved revoked key', async () => {
    const receipt = await loadJson('valid.json');
    const result = await verifyReceipt(receipt, { keyUrl: await remoteKeyUrl('revoked') });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(4);
      expect(result.errorCode).toBe('KEY_RESOLUTION_FAILED');
      expect(result.errorMessage).toBe('key "pp-test-2026-q2" is revoked');
    }
  });

  it('rejects an explicit unknown remote key status', async () => {
    const receipt = await loadJson('valid.json');
    const result = await verifyReceipt(receipt, { keyUrl: await remoteKeyUrl('disabled') });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.exitCode).toBe(4);
      expect(result.errorCode).toBe('KEY_RESOLUTION_FAILED');
      expect(result.errorMessage).toBe('key "pp-test-2026-q2" has unsupported status "disabled"');
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
