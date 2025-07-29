/**
 * @synet/crypto - Foundational Cryptographic Unit
 * 
 * Zero-dependency cryptographic operations following Unit Architecture doctrine.
 * 
 * EXPORTS:
 * - CryptoUnit: Complete conscious crypto unit with teach/learn capabilities
 * - Pure functions: Simple functional crypto operations  
 * - Result: Foundational error handling pattern
 * - Types: All crypto-related interfaces
 */

// Core Unit
export { Crypto } from './crypto.unit.js';

// Result pattern (foundational)
export { Result } from './result.js';

// Types
export type {
  CryptoConfig,
  CryptoProps, 
  CryptoCapabilities,
  EncryptedData,
  KeyPair,
  HashResult,
  KeyDerivationResult
} from './crypto.unit.js';

// Pure function exports for simple use cases
export { 
  encrypt,
  decrypt,
  hash,
  generateKey,
  generateKeyPair,
  sign,
  verify,
  randomBytes,
  deriveKeyPBKDF2,
  deriveKeyHKDF,
  deriveKeyScrypt
} from './functions.js';
