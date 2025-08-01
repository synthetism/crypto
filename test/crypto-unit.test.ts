/**
 * Crypto Unit Tests - Core Unit Architecture and Cryptographic Operations
 * 
 * Tests Unit Architecture v1.0.5 compliance and all crypto operations
 */

import { describe, test, expect, beforeEach } from 'vitest';
import { Crypto, type CryptoConfig } from '../src/crypto.unit.js';

describe('Crypto Unit - Unit Architecture Compliance', () => {
  let crypto: Crypto;

  beforeEach(() => {
    crypto = Crypto.create();
  });

  test('Unit Identity & DNA', () => {
    // Doctrine #7: EVERY UNIT MUST HAVE DNA
    expect(crypto.dna).toBeDefined();
    expect(crypto.dna.id).toBe('crypto');
    expect(crypto.dna.version).toBe('1.0.0');

    // Unit consciousness
    expect(crypto.whoami()).toContain('CryptoUnit');
    expect(crypto.whoami()).toContain('crypto');
  });


  test('Teaching Contract - Doctrine #9: ALWAYS TEACH', () => {
    const contract = crypto.teach();
    
    // Must have unit ID for namespacing (Doctrine #12)
    expect(contract.unitId).toBe('crypto');
    expect(contract.capabilities).toBeDefined();
    
    // Should teach native capabilities only (Doctrine #19)
    expect(contract.capabilities.encrypt).toBeDefined();
    expect(contract.capabilities.decrypt).toBeDefined();
    expect(contract.capabilities.hash).toBeDefined();
    expect(contract.capabilities.sign).toBeDefined();
    expect(contract.capabilities.verify).toBeDefined();
    expect(contract.capabilities.deriveKeyPBKDF2).toBeDefined();
    expect(contract.capabilities.deriveKeyHKDF).toBeDefined();
    expect(contract.capabilities.deriveKeyScrypt).toBeDefined();
    
    expect(typeof contract.capabilities.encrypt).toBe('function');
    expect(typeof contract.capabilities.hash).toBe('function');
  });

  test('Learning Capabilities - Doctrine #2: TEACH/LEARN PARADIGM', () => {
    // Create mock teaching contract
    const mockContract = {
      unitId: 'test-unit',
      capabilities: {
        mockCapability: (...args: unknown[]) => 'mock result'
      }
    };

    crypto.learn([mockContract]);
    
    // Should have learned the capability
    expect(crypto.can('test-unit.mockCapability')).toBe(true);
  });

  test('Help Documentation - Doctrine #11: ALWAYS HELP', () => {
    // Should not throw when providing help
    expect(() => crypto.help()).not.toThrow();
  });

 
});

describe('Crypto Unit - Core Cryptographic Operations', () => {
  let crypto: Crypto;

  beforeEach(() => {
    crypto = Crypto.create();
  });

  describe('Key Generation', () => {
    test('generateKey - should generate secure keys', () => {
      const key32 = crypto.generateKey(32);
      const key64 = crypto.generateKey(64);
      
      expect(key32).toHaveLength(64); // 32 bytes = 64 hex chars
      expect(key64).toHaveLength(128); // 64 bytes = 128 hex chars
      expect(key32).toMatch(/^[0-9a-f]+$/); // Hex only
      expect(key32).not.toBe(key64); // Should be different
    });

    test('generateKeyPair - RSA keys', () => {
      const keyPair = crypto.generateKeyPair('rsa', 2048);
      
      expect(keyPair.algorithm).toBe('rsa');
      expect(keyPair.keySize).toBe(2048);
      expect(keyPair.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keyPair.privateKey).toContain('BEGIN PRIVATE KEY');
    });

    test('generateKeyPair - EC keys', () => {
      const keyPair = crypto.generateKeyPair('ec');
      
      expect(keyPair.algorithm).toBe('ec');
      expect(keyPair.keySize).toBe(256); // Fixed for prime256v1
      expect(keyPair.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keyPair.privateKey).toContain('BEGIN PRIVATE KEY');
    });

    test('randomBytes - should generate random data', () => {
      const bytes16 = crypto.randomBytes(16);
      const bytes32 = crypto.randomBytes(32);
      
      expect(bytes16).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(bytes32).toHaveLength(64); // 32 bytes = 64 hex chars
      expect(bytes16).toMatch(/^[0-9a-f]+$/);
      expect(bytes16).not.toBe(bytes32);
    });
  });

  describe('Symmetric Encryption', () => {
    test('encrypt/decrypt - successful round trip', () => {
      const data = 'Sensitive test data for encryption';
      const key = crypto.generateKey(32);
      
      const encryptResult = crypto.encrypt(data, key);
      expect(encryptResult.isSuccess).toBe(true);
      
      if (encryptResult.isSuccess) {
        const encrypted = encryptResult.value;
        expect(encrypted.data).toBeDefined();
        expect(encrypted.iv).toBeDefined();
        expect(encrypted.tag).toBeDefined(); // GCM mode has auth tag
        expect(encrypted.algorithm).toBe('aes-256-gcm');
        
        const decryptResult = crypto.decrypt(encrypted, key);
        expect(decryptResult.isSuccess).toBe(true);
        
        if (decryptResult.isSuccess) {
          expect(decryptResult.value).toBe(data);
        }
      }
    });

    test('encrypt - should fail with invalid key', () => {
      const data = 'Test data';
      const invalidKey = 'not-a-valid-hex-key';
      
      const result = crypto.encrypt(data, invalidKey);
      expect(result.isSuccess).toBe(false);
    });

    test('decrypt - should fail with wrong key', () => {
      const data = 'Test data';
      const key1 = crypto.generateKey(32);
      const key2 = crypto.generateKey(32);
      
      const encryptResult = crypto.encrypt(data, key1);
      expect(encryptResult.isSuccess).toBe(true);
      
      if (encryptResult.isSuccess) {
        const decryptResult = crypto.decrypt(encryptResult.value, key2);
        expect(decryptResult.isSuccess).toBe(false);
        if (decryptResult.isFailure) {
          expect(decryptResult.error).toContain('[crypto] Decryption failed');
          expect(decryptResult.errorCause).toBeDefined();
        }
      }
    });
  });

  describe('Cryptographic Hashing', () => {
    test('hash - should generate consistent hashes', () => {
      const data = 'Data to hash';
      
      const hash1 = crypto.hash(data);
      const hash2 = crypto.hash(data);
      
      expect(hash1.hash).toBe(hash2.hash);
      expect(hash1.algorithm).toBe('sha256');
      expect(hash1.input).toBe(data);
      expect(hash1.timestamp).toBeInstanceOf(Date);
    });

    test('hash - different algorithms', () => {
      const data = 'Test data';
      
      const sha256 = crypto.hash(data, 'sha256');
      const sha512 = crypto.hash(data, 'sha512');
      
      expect(sha256.hash).not.toBe(sha512.hash);
      expect(sha256.algorithm).toBe('sha256');
      expect(sha512.algorithm).toBe('sha512');
      expect(sha256.hash).toHaveLength(64); // SHA256 = 32 bytes = 64 hex
      expect(sha512.hash).toHaveLength(128); // SHA512 = 64 bytes = 128 hex
    });
  });

  describe('Digital Signatures', () => {
    test('sign/verify - successful round trip', () => {
      const data = 'Document to sign';
      const keyPair = crypto.generateKeyPair('rsa', 2048);
      
      const signResult = crypto.sign(data, keyPair.privateKey);
      expect(signResult.isSuccess).toBe(true);
      
      if (signResult.isSuccess) {
        const signature = signResult.value;
        
        const verifyResult = crypto.verify(data, signature, keyPair.publicKey);
        expect(verifyResult.isSuccess).toBe(true);
        
        if (verifyResult.isSuccess) {
          expect(verifyResult.value).toBe(true);
        }
      }
    });

    test('verify - should return false for malformed signature', () => {
      const data = 'Document to sign';
      const keyPair = crypto.generateKeyPair('rsa', 2048);
      const malformedSignature = 'not-hex-signature';
      
      const verifyResult = crypto.verify(data, malformedSignature, keyPair.publicKey);
      expect(verifyResult.isSuccess).toBe(true);
      if (verifyResult.isSuccess) {
        expect(verifyResult.value).toBe(false);
      }
    });

    test('verify - should fail with tampered data', () => {
      const data = 'Original document';
      const tamperedData = 'Tampered document';
      const keyPair = crypto.generateKeyPair('rsa', 2048);
      
      const signResult = crypto.sign(data, keyPair.privateKey);
      expect(signResult.isSuccess).toBe(true);
      
      if (signResult.isSuccess) {
        const signature = signResult.value;
        
        const verifyResult = crypto.verify(tamperedData, signature, keyPair.publicKey);
        expect(verifyResult.isSuccess).toBe(true);
        
        if (verifyResult.isSuccess) {
          expect(verifyResult.value).toBe(false);
        }
      }
    });
  });

  describe('Key Derivation Functions', () => {
    test('deriveKeyPBKDF2 - should derive consistent keys', () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(16);
      
      const result1 = crypto.deriveKeyPBKDF2(password, salt, 1000);
      const result2 = crypto.deriveKeyPBKDF2(password, salt, 1000);
      
      expect(result1.derivedKey).toBe(result2.derivedKey);
      expect(result1.algorithm).toBe('pbkdf2');
      expect(result1.iterations).toBe(1000);
      expect(result1.keyLength).toBe(32);
      expect(result1.salt).toBe(salt);
      expect(result1.timestamp).toBeInstanceOf(Date);
    });

    test('deriveKeyPBKDF2 - different passwords should give different keys', () => {
      const salt = crypto.randomBytes(16);
      
      const result1 = crypto.deriveKeyPBKDF2('password1', salt, 1000);
      const result2 = crypto.deriveKeyPBKDF2('password2', salt, 1000);
      
      expect(result1.derivedKey).not.toBe(result2.derivedKey);
    });

    test('deriveKeyHKDF - should derive keys for protocols', () => {
      const keyMaterial = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      const info = 'test-protocol';
      
      const result1 = crypto.deriveKeyHKDF(keyMaterial, salt, info);
      const result2 = crypto.deriveKeyHKDF(keyMaterial, salt, info);
      
      expect(result1.derivedKey).toBe(result2.derivedKey);
      expect(result1.algorithm).toBe('hkdf-sha256');
      expect(result1.keyLength).toBe(32);
      expect(result1.salt).toBe(salt);
    });

    test('deriveKeyHKDF - different info should give different keys', () => {
      const keyMaterial = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      
      const result1 = crypto.deriveKeyHKDF(keyMaterial, salt, 'info1');
      const result2 = crypto.deriveKeyHKDF(keyMaterial, salt, 'info2');
      
      expect(result1.derivedKey).not.toBe(result2.derivedKey);
    });

    test('deriveKeyScrypt - should derive memory-hard keys', () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(16);
      const options = { N: 1024, r: 8, p: 1 }; // Lower N for faster tests
      
      const result1 = crypto.deriveKeyScrypt(password, salt, 32, options);
      const result2 = crypto.deriveKeyScrypt(password, salt, 32, options);
      
      expect(result1.derivedKey).toBe(result2.derivedKey);
      expect(result1.algorithm).toBe('scrypt-N1024-r8-p1');
      expect(result1.keyLength).toBe(32);
      expect(result1.salt).toBe(salt);
    });

    test('deriveKeyScrypt - different parameters should give different keys', () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(16);
      
      const result1 = crypto.deriveKeyScrypt(password, salt, 32, { N: 1024 });
      const result2 = crypto.deriveKeyScrypt(password, salt, 32, { N: 2048 });
      
      expect(result1.derivedKey).not.toBe(result2.derivedKey);
    });
  });
});
