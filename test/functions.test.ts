/**
 * Pure Functions Tests - Serverless-Ready Cryptographic Operations
 * 
 * Tests all pure function wrappers for serverless deployment compatibility
 */

import { describe, test, expect } from 'vitest';
import {
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
} from '../src/functions.js';

describe('Pure Functions - Serverless Cryptographic Operations', () => {
  
  describe('Key Generation Functions', () => {
    test('generateKey - should create secure keys', () => {
      const key16 = generateKey(16);
      const key32 = generateKey(32);
      const key64 = generateKey(64);
      
      expect(key16).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(key32).toHaveLength(64); // 32 bytes = 64 hex chars
      expect(key64).toHaveLength(128); // 64 bytes = 128 hex chars
      
      // Each call should generate unique keys
      expect(key16).not.toBe(key32);
      expect(key32).not.toBe(key64);
      
      // Should only contain hex characters
      expect(key16).toMatch(/^[0-9a-f]+$/);
      expect(key32).toMatch(/^[0-9a-f]+$/);
    });

    test('generateKeyPair - RSA key pairs', () => {
      const keyPair2048 = generateKeyPair('rsa', 2048);
      const keyPair4096 = generateKeyPair('rsa', 4096);
      
      expect(keyPair2048.algorithm).toBe('rsa');
      expect(keyPair2048.keySize).toBe(2048);
      expect(keyPair2048.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keyPair2048.privateKey).toContain('BEGIN PRIVATE KEY');
      
      expect(keyPair4096.keySize).toBe(4096);
      expect(keyPair2048.publicKey).not.toBe(keyPair4096.publicKey);
    });

    test('generateKeyPair - EC key pairs', () => {
      const ecKeyPair = generateKeyPair('ec');
      
      expect(ecKeyPair.algorithm).toBe('ec');
      expect(ecKeyPair.keySize).toBe(256);
      expect(ecKeyPair.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(ecKeyPair.privateKey).toContain('BEGIN PRIVATE KEY');
    });

    test('randomBytes - should generate random data', () => {
      const bytes8 = randomBytes(8);
      const bytes16 = randomBytes(16);
      const bytes32 = randomBytes(32);
      
      expect(bytes8).toHaveLength(16); // 8 bytes = 16 hex chars
      expect(bytes16).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(bytes32).toHaveLength(64); // 32 bytes = 64 hex chars
      
      // Each call should be unique
      expect(bytes8).not.toBe(bytes16);
      expect(bytes16).not.toBe(bytes32);
      
      // Should only contain hex characters
      expect(bytes8).toMatch(/^[0-9a-f]+$/);
    });
  });

  describe('Symmetric Encryption Functions', () => {
    test('encrypt/decrypt - successful round trip', () => {
      const originalData = 'This is sensitive test data for encryption testing';
      const encryptionKey = generateKey(32);
      
      // Test encryption
      const encryptResult = encrypt(originalData, encryptionKey);
      expect(encryptResult.isSuccess).toBe(true);
      
      if (encryptResult.isSuccess) {
        const encryptedData = encryptResult.value;
        
        expect(encryptedData.data).toBeDefined();
        expect(encryptedData.iv).toBeDefined();
        expect(encryptedData.tag).toBeDefined();
        expect(encryptedData.algorithm).toBe('aes-256-gcm');
        
        // Test decryption
        const decryptResult = decrypt(encryptedData, encryptionKey);
        expect(decryptResult.isSuccess).toBe(true);
        
        if (decryptResult.isSuccess) {
          expect(decryptResult.value).toBe(originalData);
        }
      }
    });

    test('encrypt - should fail with malformed key', () => {
      const data = 'Test data';
      const badKey = 'not-a-valid-hex-key-format';
      
      const result = encrypt(data, badKey);
      expect(result.isSuccess).toBe(false);
    });

    test('decrypt - should fail with wrong key', () => {
      const data = 'Test data';
      const correctKey = generateKey(32);
      const wrongKey = generateKey(32);
      
      const encryptResult = encrypt(data, correctKey);
      expect(encryptResult.isSuccess).toBe(true);
      
      if (encryptResult.isSuccess) {
        const decryptResult = decrypt(encryptResult.value, wrongKey);
        expect(decryptResult.isSuccess).toBe(false);
      }
    });

    test('encrypt/decrypt - multiple operations are stateless', () => {
      const data1 = 'First data set';
      const data2 = 'Second data set';
      const key1 = generateKey(32);
      const key2 = generateKey(32);
      
      // Parallel operations should not interfere
      const encrypt1 = encrypt(data1, key1);
      const encrypt2 = encrypt(data2, key2);
      
      expect(encrypt1.isSuccess).toBe(true);
      expect(encrypt2.isSuccess).toBe(true);
      
      if (encrypt1.isSuccess && encrypt2.isSuccess) {
        const decrypt1 = decrypt(encrypt1.value, key1);
        const decrypt2 = decrypt(encrypt2.value, key2);
        
        expect(decrypt1.isSuccess).toBe(true);
        expect(decrypt2.isSuccess).toBe(true);
        
        if (decrypt1.isSuccess && decrypt2.isSuccess) {
          expect(decrypt1.value).toBe(data1);
          expect(decrypt2.value).toBe(data2);
        }
      }
    });
  });

  describe('Cryptographic Hash Functions', () => {
    test('hash - should generate consistent hashes', () => {
      const testData = 'Consistent data for hashing';
      
      const hash1 = hash(testData);
      const hash2 = hash(testData);
      const hash3 = hash(testData, 'sha256');
      
      expect(hash1.hash).toBe(hash2.hash);
      expect(hash1.hash).toBe(hash3.hash);
      expect(hash1.algorithm).toBe('sha256');
      expect(hash1.input).toBe(testData);
    });

    test('hash - different algorithms produce different results', () => {
      const testData = 'Test data for algorithm comparison';
      
      const sha256Hash = hash(testData, 'sha256');
      const sha512Hash = hash(testData, 'sha512');
      const sha1Hash = hash(testData, 'sha1');
      
      expect(sha256Hash.hash).not.toBe(sha512Hash.hash);
      expect(sha256Hash.hash).not.toBe(sha1Hash.hash);
      
      expect(sha256Hash.algorithm).toBe('sha256');
      expect(sha512Hash.algorithm).toBe('sha512');
      expect(sha1Hash.algorithm).toBe('sha1');
      
      // Check expected hash lengths
      expect(sha256Hash.hash).toHaveLength(64); // 32 bytes = 64 hex
      expect(sha512Hash.hash).toHaveLength(128); // 64 bytes = 128 hex
      expect(sha1Hash.hash).toHaveLength(40); // 20 bytes = 40 hex
    });

    test('hash - different data produces different hashes', () => {
      const data1 = 'First data set';
      const data2 = 'Second data set';
      
      const hash1 = hash(data1);
      const hash2 = hash(data2);
      
      expect(hash1.hash).not.toBe(hash2.hash);
      expect(hash1.input).toBe(data1);
      expect(hash2.input).toBe(data2);
    });
  });

  describe('Digital Signature Functions', () => {
    test('sign/verify - RSA signature round trip', () => {
      const document = 'Important document requiring digital signature';
      const keyPair = generateKeyPair('rsa', 2048);
      
      // Test signing
      const signResult = sign(document, keyPair.privateKey);
      expect(signResult.isSuccess).toBe(true);
      
      if (signResult.isSuccess) {
        const signature = signResult.value;
        expect(signature).toBeDefined();
        expect(signature.length).toBeGreaterThan(0);
        
        // Test verification
        const verifyResult = verify(document, signature, keyPair.publicKey);
        expect(verifyResult.isSuccess).toBe(true);
        
        if (verifyResult.isSuccess) {
          expect(verifyResult.value).toBe(true);
        }
      }
    });

    test('sign/verify - EC signature round trip', () => {
      const document = 'Document for EC signature testing';
      const keyPair = generateKeyPair('ec');
      
      const signResult = sign(document, keyPair.privateKey);
      expect(signResult.isSuccess).toBe(true);
      
      if (signResult.isSuccess) {
        const signature = signResult.value;
        
        const verifyResult = verify(document, signature, keyPair.publicKey);
        expect(verifyResult.isSuccess).toBe(true);
        
        if (verifyResult.isSuccess) {
          expect(verifyResult.value).toBe(true);
        }
      }
    });

    test('verify - should detect tampered documents', () => {
      const originalDoc = 'Original authentic document';
      const tamperedDoc = 'Tampered malicious document';
      const keyPair = generateKeyPair('rsa', 2048);
      
      const signResult = sign(originalDoc, keyPair.privateKey);
      expect(signResult.isSuccess).toBe(true);
      
      if (signResult.isSuccess) {
        const signature = signResult.value;
        
        // Verify original should pass
        const originalVerify = verify(originalDoc, signature, keyPair.publicKey);
        expect(originalVerify.isSuccess).toBe(true);
        if (originalVerify.isSuccess) {
          expect(originalVerify.value).toBe(true);
        }
        
        // Verify tampered should fail
        const tamperedVerify = verify(tamperedDoc, signature, keyPair.publicKey);
        expect(tamperedVerify.isSuccess).toBe(true);
        if (tamperedVerify.isSuccess) {
          expect(tamperedVerify.value).toBe(false);
        }
      }
    });

    test('verify - should return false for malformed signature', () => {
      const document = 'Test document';
      const keyPair = generateKeyPair('rsa', 2048);
      const malformedSignature = 'not-hex-signature-format';
      
      const verifyResult = verify(document, malformedSignature, keyPair.publicKey);
      expect(verifyResult.isSuccess).toBe(true);
      if (verifyResult.isSuccess) {
        expect(verifyResult.value).toBe(false);
      }
    });
  });

  describe('Key Derivation Functions', () => {
    test('deriveKeyPBKDF2 - password-based key derivation', () => {
      const password = 'user-secure-password';
      const salt = randomBytes(16);
      const iterations = 50000; // Reduced for test performance
      
      // Same inputs should produce same results
      const result1 = deriveKeyPBKDF2(password, salt, iterations);
      const result2 = deriveKeyPBKDF2(password, salt, iterations);
      
      expect(result1.derivedKey).toBe(result2.derivedKey);
      expect(result1.algorithm).toBe('pbkdf2');
      expect(result1.iterations).toBe(iterations);
      expect(result1.keyLength).toBe(32);
      expect(result1.salt).toBe(salt);
      
      // Different passwords should produce different keys
      const result3 = deriveKeyPBKDF2('different-password', salt, iterations);
      expect(result1.derivedKey).not.toBe(result3.derivedKey);
    });

    test('deriveKeyPBKDF2 - different parameters produce different keys', () => {
      const password = 'test-password';
      const salt1 = randomBytes(16);
      const salt2 = randomBytes(16);
      
      const result1 = deriveKeyPBKDF2(password, salt1, 1000);
      const result2 = deriveKeyPBKDF2(password, salt2, 1000);
      const result3 = deriveKeyPBKDF2(password, salt1, 2000);
      
      // Different salts should produce different keys
      expect(result1.derivedKey).not.toBe(result2.derivedKey);
      
      // Different iterations should produce different keys
      expect(result1.derivedKey).not.toBe(result3.derivedKey);
    });

    test('deriveKeyHKDF - extract-and-expand key derivation', () => {
      const inputKeyMaterial = randomBytes(32);
      const salt = randomBytes(16);
      const info = 'test-protocol-context';
      
      // Same inputs should produce same results
      const result1 = deriveKeyHKDF(inputKeyMaterial, salt, info);
      const result2 = deriveKeyHKDF(inputKeyMaterial, salt, info);
      
      expect(result1.derivedKey).toBe(result2.derivedKey);
      expect(result1.algorithm).toBe('hkdf-sha256');
      expect(result1.keyLength).toBe(32);
      expect(result1.salt).toBe(salt);
      
      // Different info should produce different keys
      const result3 = deriveKeyHKDF(inputKeyMaterial, salt, 'different-context');
      expect(result1.derivedKey).not.toBe(result3.derivedKey);
    });

    test('deriveKeyHKDF - different key lengths', () => {
      const inputKeyMaterial = randomBytes(32);
      const salt = randomBytes(16);
      const info = 'test-protocol';
      
      const key16 = deriveKeyHKDF(inputKeyMaterial, salt, info, 16);
      const key32 = deriveKeyHKDF(inputKeyMaterial, salt, info, 32);
      const key64 = deriveKeyHKDF(inputKeyMaterial, salt, info, 64);
      
      expect(key16.keyLength).toBe(16);
      expect(key32.keyLength).toBe(32);
      expect(key64.keyLength).toBe(64);
      
      expect(key16.derivedKey).toHaveLength(32); // 16 bytes = 32 hex
      expect(key32.derivedKey).toHaveLength(64); // 32 bytes = 64 hex
      expect(key64.derivedKey).toHaveLength(128); // 64 bytes = 128 hex
    });

    test('deriveKeyScrypt - memory-hard key derivation', () => {
      const password = 'user-password';
      const salt = randomBytes(16);
      const options = { N: 1024, r: 8, p: 1 }; // Lower values for test performance
      
      // Same inputs should produce same results
      const result1 = deriveKeyScrypt(password, salt, 32, options);
      const result2 = deriveKeyScrypt(password, salt, 32, options);
      
      expect(result1.derivedKey).toBe(result2.derivedKey);
      expect(result1.algorithm).toBe('scrypt-N1024-r8-p1');
      expect(result1.keyLength).toBe(32);
      expect(result1.salt).toBe(salt);
      
      // Different passwords should produce different keys
      const result3 = deriveKeyScrypt('different-password', salt, 32, options);
      expect(result1.derivedKey).not.toBe(result3.derivedKey);
    });

    test('deriveKeyScrypt - different cost parameters', () => {
      const password = 'test-password';
      const salt = randomBytes(16);
      
      const lowCost = deriveKeyScrypt(password, salt, 32, { N: 1024, r: 8, p: 1 });
      const highCost = deriveKeyScrypt(password, salt, 32, { N: 2048, r: 8, p: 1 });
      
      expect(lowCost.derivedKey).not.toBe(highCost.derivedKey);
      expect(lowCost.algorithm).toBe('scrypt-N1024-r8-p1');
      expect(highCost.algorithm).toBe('scrypt-N2048-r8-p1');
    });

    test('All key derivation functions - unique outputs', () => {
      const password = 'shared-password';
      const keyMaterial = randomBytes(32);
      const salt = randomBytes(16);
      
      const pbkdf2Result = deriveKeyPBKDF2(password, salt, 1000);
      const hkdfResult = deriveKeyHKDF(keyMaterial, salt, 'test-info');
      const scryptResult = deriveKeyScrypt(password, salt, 32, { N: 1024 });
      
      // All should produce different keys despite similar inputs
      expect(pbkdf2Result.derivedKey).not.toBe(hkdfResult.derivedKey);
      expect(pbkdf2Result.derivedKey).not.toBe(scryptResult.derivedKey);
      expect(hkdfResult.derivedKey).not.toBe(scryptResult.derivedKey);
      
      // All should use different algorithms
      expect(pbkdf2Result.algorithm).toBe('pbkdf2');
      expect(hkdfResult.algorithm).toBe('hkdf-sha256');
      expect(scryptResult.algorithm).toBe('scrypt-N1024-r8-p1');
    });
  });

  describe('Stateless Operation Validation', () => {
    test('All functions should be stateless and thread-safe', async () => {
      const password = 'test-password';
      const data = 'test-data';
      const salt = randomBytes(16);
      
      // Run multiple operations concurrently
      const promises = Array.from({ length: 10 }, async (_, i) => {
        const key = generateKey(32);
        const hashResult = hash(`${data}-${i}`);
        const kdfResult = deriveKeyPBKDF2(`${password}-${i}`, salt, 1000);
        
        return { key, hashResult, kdfResult, index: i };
      });
      
      const results = await Promise.all(promises);
      
      // All should complete successfully
      expect(results).toHaveLength(10);
      
      // Each should be unique (no shared state pollution)
      const keys = results.map(r => r.key);
      const hashes = results.map(r => r.hashResult.hash);
      const kdfs = results.map(r => r.kdfResult.derivedKey);
      
      // All keys should be unique
      expect(new Set(keys).size).toBe(10);
      expect(new Set(hashes).size).toBe(10);
      expect(new Set(kdfs).size).toBe(10);
    });
  });
});
