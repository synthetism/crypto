/**
 * Pure Functions for Serverless Crypto Operations
 * 
 * These are stateless wrappers around the Crypto unit for deployment to
 * Cloudflare Workers, AWS Lambda, and other serverless platforms.
 * 
 * Each function creates a fresh Crypto unit, executes the operation, and returns the result.
 * No state is maintained between calls - perfect for serverless environments.
 */

import { Crypto, type EncryptedData, type KeyPair, type HashResult } from './crypto.unit.js';
import { Result } from './result.js';

/**
 * Pure symmetric encryption function
 */
export async function encrypt(data: string, key: string): Promise<Result<EncryptedData>> {
  const crypto = Crypto.create();
  return crypto.encrypt(data, key);
}

/**
 * Pure symmetric decryption function
 */
export async function decrypt(encrypted: EncryptedData, key: string): Promise<Result<string>> {
  const crypto = Crypto.create();
  return crypto.decrypt(encrypted, key);
}

/**
 * Pure hash function
 */
export function hash(data: string, algorithm?: string): HashResult {
  const crypto = Crypto.create({ hashAlgorithm: algorithm as any });
  return crypto.hash(data, algorithm);
}

/**
 * Pure key generation function
 */
export function generateKey(size: number = 32): string {
  const crypto = Crypto.create();
  return crypto.generateKey(size);
}

/**
 * Pure key pair generation function
 */
export function generateKeyPair(algorithm: 'rsa' | 'ec' = 'rsa', keySize?: number): KeyPair {
  const crypto = Crypto.create({ keySize: keySize as 256 | 512 | 1024 | 2048 | 4096 });
  return crypto.generateKeyPair(algorithm, keySize);
}

/**
 * Pure signature function
 */
export async function sign(data: string, privateKey: string): Promise<Result<string>> {
  const crypto = Crypto.create();
  return crypto.sign(data, privateKey);
}

/**
 * Pure verification function
 */
export async function verify(data: string, signature: string, publicKey: string): Promise<Result<boolean>> {
  const crypto = Crypto.create();
  return crypto.verify(data, signature, publicKey);
}

/**
 * Pure random bytes function
 */
export function randomBytes(size: number): string {
  const crypto = Crypto.create();
  return crypto.randomBytes(size);
}
