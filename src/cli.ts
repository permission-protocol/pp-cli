#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { Command } from 'commander';
import { verifyReceipt } from './verify.js';

type VerifyCliOptions = {
  keyUrl?: string;
  keyFile?: string;
  keyId?: string;
  json?: boolean;
  quiet?: boolean;
  network?: boolean;
};

function looksLikeReceiptUrl(input: string): boolean {
  return /^https?:\/\//.test(input);
}

function extractReceiptId(input: string): string | null {
  if (input.startsWith('rcpt_')) {
    return input;
  }

  if (looksLikeReceiptUrl(input)) {
    try {
      const url = new URL(input);
      const parts = url.pathname.split('/').filter(Boolean);
      const tail = parts.at(-1);
      if (tail?.startsWith('rcpt_')) {
        return tail;
      }
    } catch {
      return null;
    }
  }

  return null;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function loadReceipt(input: string, noNetwork?: boolean): Promise<unknown> {
  if (input === '-') {
    return JSON.parse(await readStdin());
  }

  const receiptId = extractReceiptId(input);
  if (receiptId) {
    if (noNetwork) {
      throw new Error('network access disabled by --no-network; receipt IDs/URLs require network access');
    }
    const response = await fetch(`https://app.permissionprotocol.com/api/v1/receipts/${receiptId}`);
    if (!response.ok) {
      throw new Error(`failed to fetch receipt ${receiptId}: ${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  return JSON.parse(await readFile(input, 'utf8'));
}

function printHumanSuccess(result: Extract<Awaited<ReturnType<typeof verifyReceipt>>, { verified: true }>): void {
  console.log(`✓ Receipt ${result.receiptId} verified`);
  console.log(`  Signer:        ${result.signer ?? 'n/a'}`);
  console.log(`  Action:        ${result.action ?? 'n/a'}`);
  console.log(`  Repo:          ${result.repo ?? 'n/a'}`);
  console.log(`  Commit:        ${result.commitSha ?? 'n/a'}`);
  console.log(`  Policy:        ${result.policy ?? 'n/a'}`);
  console.log(`  Signed:        ${result.signedAt}`);
  console.log(`  Expires:       ${result.expiresAt}`);
  console.log(`  Canonical:     ${result.canonicalization}`);
  console.log(`  Signature alg: ${result.signatureAlg}`);
  console.log(`  Key ID:        ${result.keyId}`);
  console.log(`  Verified with: ${result.keySource}`);
}

function printHumanFailure(result: Extract<Awaited<ReturnType<typeof verifyReceipt>>, { verified: false }>): void {
  console.log(`✗ Receipt ${result.receiptId ?? '<unknown>'} FAILED verification`);
  console.log(`  Reason: ${result.errorMessage}`);
}

const program = new Command();

program
  .name('pp')
  .description('Permission Protocol CLI')
  .version('0.1.0');

program
  .command('verify')
  .argument('<receipt-file-or-id>', 'Receipt file path, -, receipt id, or share URL')
  .option('--key-url <url>', 'Public key endpoint URL')
  .option('--key-file <path>', 'Path to public key PEM, base64 DER, or raw Ed25519 base64')
  .option('--key-id <id>', 'Expected key id')
  .option('--json', 'Emit machine-readable JSON output')
  .option('-q, --quiet', 'Suppress stdout and return exit code only')
  .option('--no-network', 'Disable all network calls')
  .action(async (receiptFileOrId: string, opts: VerifyCliOptions) => {
    try {
      const receipt = await loadReceipt(receiptFileOrId, opts.network === false);
      const result = await verifyReceipt(receipt, {
        keyFile: opts.keyFile,
        keyUrl: opts.keyUrl,
        keyId: opts.keyId,
        noNetwork: opts.network === false,
      });

      if (opts.quiet) {
        process.exit(result.verified ? 0 : result.exitCode);
      }

      if (opts.json) {
        if (result.verified) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(
            JSON.stringify(
              {
                verified: false,
                errorCode: result.errorCode,
                errorMessage: result.errorMessage,
                receiptId: result.receiptId,
              },
              null,
              2,
            ),
          );
        }
      } else if (result.verified) {
        printHumanSuccess(result);
      } else {
        printHumanFailure(result);
      }

      process.exit(result.verified ? 0 : result.exitCode);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const exitCode = message.includes('--no-network') ? 4 : 3;

      if (!opts.quiet) {
        if (opts.json) {
          console.log(
            JSON.stringify(
              {
                verified: false,
                errorCode: exitCode === 4 ? 'KEY_RESOLUTION_FAILED' : 'MALFORMED_RECEIPT',
                errorMessage: message,
              },
              null,
              2,
            ),
          );
        } else {
          console.error(`✗ Verification failed\n  Reason: ${message}`);
        }
      }

      process.exit(exitCode);
    }
  });

program.configureOutput({
  outputError: (str: string, write: (str: string) => void) => {
    write(str);
    process.exitCode = 64;
  },
});

program.parseAsync(process.argv);
