/**
 * Pure Functions for Serverless Crypto Operations
 * 
 * These are stateless wrappers around the Crypto unit for deployment to
 * Cloudflare Workers, AWS Lambda, and other serverless platforms.
 * 
 * Each function creates a fresh Crypto unit, executes the operation, and returns the result.
 * No state is maintained between calls - perfect for serverless environments.
 */

import { Crypto, type EncryptedData, type KeyPair, type HashResult, type KeyDerivationResult } from './crypto.unit.js';
import type { Result } from './result.js';

/**
 * Pure symmetric encryption function
 */
export function encrypt(data: string, key: string): Result<EncryptedData> {
  const crypto = Crypto.create();
  return crypto.encrypt(data, key);
}

/**
 * Pure symmetric decryption function
 */
export function decrypt(encrypted: EncryptedData, key: string): Result<string> {
  const crypto = Crypto.create();
  return crypto.decrypt(encrypted, key);
}

/**
 * Pure hash function
 */
export function hash(data: string, algorithm?: string): HashResult {
  const crypto = Crypto.create({ hashAlgorithm: algorithm as 'sha256' | 'sha512' | 'sha3-512' });
  return crypto.hash(data, algorithm);
}

/**
 * Pure key generation function
 */
export function generateKey(size = 32): string {
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
export function sign(data: string, privateKey: string): Result<string> {
  const crypto = Crypto.create();
  return crypto.sign(data, privateKey);
}

/**
 * Pure verification function
 */
export function verify(data: string, signature: string, publicKey: string): Result<boolean> {
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

/**
 * Pure PBKDF2 key derivation function
 */
export function deriveKeyPBKDF2(password: string, salt: string, iterations = 100000, keyLength = 32): KeyDerivationResult {
  const crypto = Crypto.create();
  return crypto.deriveKeyPBKDF2(password, salt, iterations, keyLength);
}

/**
 * Pure HKDF key derivation function
 */
export function deriveKeyHKDF(inputKeyMaterial: string, salt: string, info = '', keyLength = 32): KeyDerivationResult {
  const crypto = Crypto.create();
  return crypto.deriveKeyHKDF(inputKeyMaterial, salt, info, keyLength);
}

/**
 * Pure Scrypt key derivation function
 */
export function deriveKeyScrypt(password: string, salt: string, keyLength = 32, options: { N?: number; r?: number; p?: number } = {}): KeyDerivationResult {
  const crypto = Crypto.create();
  return crypto.deriveKeyScrypt(password, salt, keyLength, options);
}
