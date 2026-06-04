import { readFile, writeFile, unlink } from 'node:fs/promises';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolve } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verify.js';
import { resolvePublicKey } from '../src/keyResolver.js';

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

describe('resolvePublicKey key-type enforcement', () => {
  async function makeTmpKeyFile(keyPem: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'pp-test-'));
    const keyPath = join(dir, 'key.pem');
    await writeFile(keyPath, keyPem);
    return keyPath;
  }

  async function cleanup(keyPath: string): Promise<void> {
    const dir = keyPath.replace(/\/[^/]+$/, '');
    try {
      await rm(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }

  it('rejects RSA public keys as non-ed25519', async () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    const keyPath = await makeTmpKeyFile(pem);
    try {
      const result = await resolvePublicKey({ keyFile: keyPath, signatureKeyId: 'any' });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.errorCode).toBe('KEY_RESOLUTION_FAILED');
        expect(result.errorMessage.toLowerCase()).toContain('rsa');
      }
    } finally {
      await cleanup(keyPath);
    }
  });

  it('rejects ECDSA P-256 public keys as non-ed25519', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    const keyPath = await makeTmpKeyFile(pem);
    try {
      const result = await resolvePublicKey({ keyFile: keyPath, signatureKeyId: 'any' });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.errorCode).toBe('KEY_RESOLUTION_FAILED');
        expect(result.errorMessage.toLowerCase()).toContain('ec');
      }
    } finally {
      await cleanup(keyPath);
    }
  });
});
