import { verify as verifySignature } from 'node:crypto';
import { canonicalizeReceiptBytes, CANONICALIZATION_VERSION } from './canonicalize.js';
import { resolvePublicKey } from './keyResolver.js';

const REQUIRED_SIGNED_FIELDS = [
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

const RECEIPT_VERSION = 'v1';

const REQUIRED_STRING_FIELDS = [
  'id',
  'companyId',
  'idemKey',
  'agentId',
  'runId',
  'inputHash',
  'status',
  'riskTier',
  'policyVersion',
  'summary',
  'receiptVersion',
  'canonicalization',
  'signatureAlg',
  'signatureKeyId',
  'expiresAt',
  'createdAt',
] as const;

export type VerifyResult =
  | {
      verified: true;
      receiptId: string;
      signer?: string;
      action?: string;
      repo?: string;
      commitSha?: string;
      policy?: string;
      signedAt: string;
      expiresAt: string;
      canonicalization: string;
      signatureAlg: string;
      keyId: string;
      keySource: string;
    }
  | {
      verified: false;
      exitCode: 1 | 2 | 3 | 4;
      errorCode:
        | 'SIGNATURE_INVALID'
        | 'RECEIPT_EXPIRED_OR_REVOKED'
        | 'MALFORMED_RECEIPT'
        | 'KEY_RESOLUTION_FAILED';
      errorMessage: string;
      receiptId?: string;
    };

export type VerifyOptions = {
  keyFile?: string;
  keyUrl?: string;
  keyId?: string;
  noNetwork?: boolean;
  now?: Date;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function malformed(receipt: Record<string, unknown>, errorMessage: string): VerifyResult {
  return {
    verified: false,
    exitCode: 3,
    errorCode: 'MALFORMED_RECEIPT',
    errorMessage,
    receiptId: typeof receipt.id === 'string' ? receipt.id : undefined,
  };
}

export async function verifyReceipt(receipt: unknown, options: VerifyOptions): Promise<VerifyResult> {
  if (!isObject(receipt)) {
    return {
      verified: false,
      exitCode: 3,
      errorCode: 'MALFORMED_RECEIPT',
      errorMessage: 'receipt must be a JSON object',
    };
  }

  for (const field of REQUIRED_SIGNED_FIELDS) {
    if (!Object.hasOwn(receipt, field) || receipt[field] === undefined || receipt[field] === null) {
      return malformed(receipt, `missing required signed field: ${field}`);
    }
  }

  for (const field of REQUIRED_STRING_FIELDS) {
    if (typeof receipt[field] !== 'string') {
      return malformed(receipt, `required signed field must be a string: ${field}`);
    }
  }

  if (!isObject(receipt.requestJson) || Array.isArray(receipt.requestJson)) {
    return malformed(receipt, 'requestJson must be a JSON object');
  }

  if (!Array.isArray(receipt.reasonCodes)) {
    return malformed(receipt, 'reasonCodes must be an array');
  }

  if (receipt.receiptVersion !== RECEIPT_VERSION) {
    return malformed(receipt, 'unsupported receipt version');
  }

  if (receipt.canonicalization !== CANONICALIZATION_VERSION) {
    return {
      verified: false,
      exitCode: 3,
      errorCode: 'MALFORMED_RECEIPT',
      errorMessage: 'unsupported canonicalization version',
      receiptId: receipt.id as string,
    };
  }

  if (receipt.signatureAlg !== 'ed25519') {
    return {
      verified: false,
      exitCode: 3,
      errorCode: 'MALFORMED_RECEIPT',
      errorMessage: 'unsupported signature algorithm',
      receiptId: receipt.id as string,
    };
  }

  if (typeof receipt.signatureValue !== 'string') {
    return {
      verified: false,
      exitCode: 3,
      errorCode: 'MALFORMED_RECEIPT',
      errorMessage: 'missing signatureValue',
      receiptId: receipt.id as string,
    };
  }

  const keyResult = await resolvePublicKey({
    keyFile: options.keyFile,
    keyUrl: options.keyUrl,
    noNetwork: options.noNetwork,
    expectedKeyId: options.keyId,
    signatureKeyId: receipt.signatureKeyId as string,
  });

  if (!keyResult.ok) {
    return {
      verified: false,
      exitCode: 4,
      errorCode: 'KEY_RESOLUTION_FAILED',
      errorMessage: keyResult.errorMessage,
      receiptId: receipt.id as string,
    };
  }

  const payloadBytes = canonicalizeReceiptBytes(receipt);
  const signatureBytes = Buffer.from(receipt.signatureValue, 'base64');
  const ok = verifySignature(null, payloadBytes, keyResult.key, signatureBytes);

  if (!ok) {
    return {
      verified: false,
      exitCode: 1,
      errorCode: 'SIGNATURE_INVALID',
      errorMessage: `signature does not verify against key ${(receipt.signatureKeyId as string)}`,
      receiptId: receipt.id as string,
    };
  }

  const now = options.now ?? new Date();
  const expiresAt = new Date(receipt.expiresAt as string);
  if (Number.isNaN(expiresAt.getTime())) {
    return {
      verified: false,
      exitCode: 3,
      errorCode: 'MALFORMED_RECEIPT',
      errorMessage: 'expiresAt is not a valid ISO timestamp',
      receiptId: receipt.id as string,
    };
  }

  const status = String(receipt.status);
  if (expiresAt.getTime() <= now.getTime() || status === 'revoked') {
    return {
      verified: false,
      exitCode: 2,
      errorCode: 'RECEIPT_EXPIRED_OR_REVOKED',
      errorMessage: status === 'revoked' ? 'receipt status is revoked' : 'receipt is expired',
      receiptId: receipt.id as string,
    };
  }

  return {
    verified: true,
    receiptId: receipt.id as string,
    signer: (receipt.requestJson as Record<string, unknown>)?.signer as string | undefined,
    action: (receipt.requestJson as Record<string, unknown>)?.action as string | undefined,
    repo: (receipt.requestJson as Record<string, unknown>)?.repo as string | undefined,
    commitSha: (receipt.requestJson as Record<string, unknown>)?.commitSha as string | undefined,
    policy: receipt.policyVersion as string,
    signedAt: receipt.createdAt as string,
    expiresAt: receipt.expiresAt as string,
    canonicalization: receipt.canonicalization as string,
    signatureAlg: receipt.signatureAlg as string,
    keyId: receipt.signatureKeyId as string,
    keySource: keyResult.keySource,
  };
}
