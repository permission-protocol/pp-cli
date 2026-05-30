import { createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export const DEFAULT_KEY_URL = 'https://app.permissionprotocol.com/api/v1/keys/current';

export type ResolveKeyOptions = {
  keyFile?: string;
  keyUrl?: string;
  noNetwork?: boolean;
  expectedKeyId?: string;
  signatureKeyId: string;
};

export type ResolveKeySuccess = {
  ok: true;
  key: ReturnType<typeof createPublicKey>;
  keySource: string;
};

export type ResolveKeyFailure = {
  ok: false;
  errorCode: 'KEY_RESOLUTION_FAILED';
  errorMessage: string;
};

export type ResolveKeyResult = ResolveKeySuccess | ResolveKeyFailure;

function asPublicKey(raw: string): ReturnType<typeof createPublicKey> {
  const trimmed = raw.trim();
  const key = trimmed.includes('BEGIN PUBLIC KEY')
    ? createPublicKey(trimmed)
    : createPublicKey({ key: Buffer.from(trimmed, 'base64'), format: 'der', type: 'spki' });

  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`unsupported public key type: ${key.asymmetricKeyType ?? 'unknown'}`);
  }

  return key;
}

type RemoteKeyRecord = {
  keyId?: string;
  id?: string;
  publicKey?: string;
  key?: string;
};

function pickKeyFromPayload(payload: unknown, signatureKeyId: string): string | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }

  const obj = payload as Record<string, unknown>;
  const candidates: RemoteKeyRecord[] = [];

  if (Array.isArray(obj.keys)) {
    candidates.push(...(obj.keys as RemoteKeyRecord[]));
  }
  candidates.push(obj as RemoteKeyRecord);

  for (const candidate of candidates) {
    const id = candidate.keyId ?? candidate.id;
    if (!id || id !== signatureKeyId) {
      continue;
    }
    if (typeof candidate.publicKey === 'string') {
      return candidate.publicKey;
    }
    if (typeof candidate.key === 'string') {
      return candidate.key;
    }
  }

  return undefined;
}

export async function resolvePublicKey(options: ResolveKeyOptions): Promise<ResolveKeyResult> {
  const { keyFile, keyUrl, noNetwork, expectedKeyId, signatureKeyId } = options;

  if (expectedKeyId && expectedKeyId !== signatureKeyId) {
    return {
      ok: false,
      errorCode: 'KEY_RESOLUTION_FAILED',
      errorMessage: `receipt uses key id "${signatureKeyId}" but --key-id was "${expectedKeyId}"`,
    };
  }

  if (keyFile) {
    try {
      const contents = await readFile(keyFile, 'utf8');
      return { ok: true, key: asPublicKey(contents), keySource: keyFile };
    } catch (error) {
      return {
        ok: false,
        errorCode: 'KEY_RESOLUTION_FAILED',
        errorMessage: `failed to read key file: ${(error as Error).message}`,
      };
    }
  }

  const finalKeyUrl = keyUrl ?? DEFAULT_KEY_URL;

  if (noNetwork) {
    return {
      ok: false,
      errorCode: 'KEY_RESOLUTION_FAILED',
      errorMessage: 'network access disabled by --no-network; provide --key-file for offline verification',
    };
  }

  try {
    const response = await fetch(finalKeyUrl);
    if (!response.ok) {
      return {
        ok: false,
        errorCode: 'KEY_RESOLUTION_FAILED',
        errorMessage: `failed to fetch key URL (${response.status} ${response.statusText})`,
      };
    }

    const payload = (await response.json()) as unknown;
    const keyText = pickKeyFromPayload(payload, signatureKeyId);
    if (!keyText) {
      return {
        ok: false,
        errorCode: 'KEY_RESOLUTION_FAILED',
        errorMessage: `no key found for signature key id "${signatureKeyId}"`,
      };
    }

    return { ok: true, key: asPublicKey(keyText), keySource: finalKeyUrl };
  } catch (error) {
    return {
      ok: false,
      errorCode: 'KEY_RESOLUTION_FAILED',
      errorMessage: `failed to resolve key: ${(error as Error).message}`,
    };
  }
}
