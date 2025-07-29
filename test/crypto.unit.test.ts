/**
 * Crypto Unit Tests - Consciousness and Functionality Validation
 * 
 * Following Unit Architecture doctrine testing patterns:
 * - Identity & consciousness tests (all 22 doctrines)
 * - Core functionality validation
 * - Teaching/learning capability tests
 * - Error handling validation
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Crypto, Result, encrypt, decrypt, hash, generateKey, generateKeyPair, sign, verify } from '../src/index.js';

describe('Crypto Unit - Consciousness Tests', () => {
  let crypto: Crypto;

  beforeEach(() => {
    crypto = Crypto.create();
  });

  // Doctrine #7: EVERY UNIT MUST HAVE DNA
  it('should have valid DNA and identity', () => {
    expect(crypto.dna).toBeDefined();
    expect(crypto.dna.id).toBe('crypto-unit');
    expect(crypto.dna.version).toBe('1.0.0');
    expect(crypto.whoami()).toBe('Crypto[crypto-unit@1.0.0]');
  });

  // Doctrine #22: STATELESS OPERATIONS (expose capabilities)
  it('should expose current capabilities', () => {
    const capabilities = crypto.capabilities();
    expect(capabilities).toContain('encrypt');
    expect(capabilities).toContain('decrypt');
    expect(capabilities).toContain('hash');
    expect(capabilities).toContain('sign');
    expect(capabilities).toContain('verify');
    expect(capabilities).toContain('generateKey');
    expect(capabilities).toContain('generateKeyPair');
    expect(capabilities).toContain('randomBytes');
  });

  // Doctrine #9: ALWAYS TEACH + #12: NAMESPACE EVERYTHING  
  it('should provide teaching contract with namespaced capabilities', () => {
    const teaching = crypto.teach();
    
    expect(teaching.unitId).toBe('crypto-unit');
    expect(teaching.capabilities).toBeDefined();
    expect(teaching.capabilities.encrypt).toBeDefined();
    expect(teaching.capabilities.decrypt).toBeDefined();
    expect(teaching.capabilities.hash).toBeDefined();
    expect(teaching.capabilities.sign).toBeDefined();
    expect(teaching.capabilities.verify).toBeDefined();
    expect(teaching.capabilities.generateKey).toBeDefined();
    expect(teaching.capabilities.generateKeyPair).toBeDefined();
    expect(teaching.capabilities.randomBytes).toBeDefined();
  });

  // Doctrine #11: ALWAYS HELP (living documentation)
  it('should provide comprehensive help documentation', () => {
    // Help should not throw and should provide useful information
    expect(() => crypto.help()).not.toThrow();
  });

  // Doctrine #4: CREATE NOT CONSTRUCT (static create)
  it('should create through static factory method', () => {
    const customCrypto = Crypto.create({
      algorithm: 'aes-128-gcm',
      keySize: 4096,
      hashAlgorithm: 'sha512'
    });
    
    expect(customCrypto).toBeInstanceOf(Crypto);
    expect(customCrypto.dna.id).toBe('crypto-unit');
  });

  // Doctrine #13: TYPE HIERARCHY CONSISTENCY  
  it('should export domain representation', () => {
    const domain = crypto.toDomain();
    
    expect(domain).toHaveProperty('encrypt');
    expect(domain).toHaveProperty('decrypt');
    expect(domain).toHaveProperty('hash');
    expect(domain).toHaveProperty('sign');
    expect(domain).toHaveProperty('verify');
  });

  // Doctrine #17: VALUE OBJECT FOUNDATION (immutable)
  it('should be immutable value object', () => {
    const json = crypto.toJSON();
    
    expect(json.type).toBe('Crypto');
    expect(json.dna).toEqual(crypto.dna);
    expect(json.capabilities).toBeDefined();
  });
});

describe('Crypto Unit - Core Functionality', () => {
  let crypto: Crypto;

  beforeEach(() => {
    crypto = Crypto.create();
  });

  // Symmetric Encryption Tests
  it('should encrypt and decrypt data successfully', async () => {
    const keyResult = crypto.generateKey();
    expect(keyResult.isSuccess).toBe(true);
    
    const key = keyResult.value;
    const data = 'Hello, World!';
    
    const encryptResult = await crypto.encrypt(data, key);
    expect(encryptResult.isSuccess).toBe(true);
    
    const encrypted = encryptResult.value;
    expect(encrypted.data).toBeDefined();
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.algorithm).toBe('aes-256-gcm');
    expect(encrypted.tag).toBeDefined(); // GCM mode should have auth tag
    
    const decryptResult = await crypto.decrypt(encrypted, key);
    expect(decryptResult.isSuccess).toBe(true);
    expect(decryptResult.value).toBe(data);
  });

  // Hash Tests
  it('should generate consistent hashes', () => {
    const data = 'test data';
    
    const hashResult1 = crypto.hash(data);
    const hashResult2 = crypto.hash(data);
    
    expect(hashResult1.isSuccess).toBe(true);
    expect(hashResult2.isSuccess).toBe(true);
    expect(hashResult1.value.hash).toBe(hashResult2.value.hash);
    expect(hashResult1.value.algorithm).toBe('sha256');
    expect(hashResult1.value.input).toBe(data);
  });

  // Key Generation Tests
  it('should generate encryption keys', () => {
    const keyResult = crypto.generateKey();
    
    expect(keyResult.isSuccess).toBe(true);
    expect(keyResult.value).toMatch(/^[a-f0-9]{64}$/); // 32 bytes = 64 hex chars
  });

  // Key Pair Generation Tests
  it('should generate RSA key pairs', () => {
    const keyPairResult = crypto.generateKeyPair('rsa', 2048);
    
    expect(keyPairResult.isSuccess).toBe(true);
    const keyPair = keyPairResult.value;
    expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    expect(keyPair.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    expect(keyPair.algorithm).toBe('rsa');
    expect(keyPair.keySize).toBe(2048);
  });

  it('should generate EC key pairs', () => {
    const keyPairResult = crypto.generateKeyPair('ec');
    
    expect(keyPairResult.isSuccess).toBe(true);
    const keyPair = keyPairResult.value;
    expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    expect(keyPair.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    expect(keyPair.algorithm).toBe('ec');
    expect(keyPair.keySize).toBe(256);
  });

  // Digital Signature Tests
  it('should sign and verify data', async () => {
    const keyPairResult = crypto.generateKeyPair('rsa', 2048);
    expect(keyPairResult.isSuccess).toBe(true);
    
    const keyPair = keyPairResult.value;
    const data = 'document to sign';
    
    const signResult = await crypto.sign(data, keyPair.privateKey);
    expect(signResult.isSuccess).toBe(true);
    
    const signature = signResult.value;
    expect(signature).toMatch(/^[a-f0-9]+$/); // Hex signature
    
    const verifyResult = await crypto.verify(data, signature, keyPair.publicKey);
    expect(verifyResult.isSuccess).toBe(true);
    expect(verifyResult.value).toBe(true);
    
    // Test with wrong data
    const verifyWrongResult = await crypto.verify('wrong data', signature, keyPair.publicKey);
    expect(verifyWrongResult.isSuccess).toBe(true);
    expect(verifyWrongResult.value).toBe(false);
  });

  // Random Bytes Tests
  it('should generate random bytes', () => {
    const randomResult1 = crypto.randomBytes(16);
    const randomResult2 = crypto.randomBytes(16);
    
    expect(randomResult1.isSuccess).toBe(true);
    expect(randomResult2.isSuccess).toBe(true);
    expect(randomResult1.value).toMatch(/^[a-f0-9]{32}$/); // 16 bytes = 32 hex chars
    expect(randomResult1.value).not.toBe(randomResult2.value); // Should be random
  });
});

describe('Crypto Unit - Error Handling', () => {
  let crypto: Crypto;

  beforeEach(() => {
    crypto = Crypto.create();
  });

  // Doctrine #14: ERROR BOUNDARY CLARITY (Result for expected failures)
  it('should handle invalid keys gracefully', async () => {
    const encryptResult = await crypto.encrypt('data', 'invalid-key');
    expect(encryptResult.isFailure).toBe(true);
    expect(encryptResult.errorMessage).toBeDefined();
  });

  it('should handle invalid encrypted data gracefully', async () => {
    const invalidEncrypted = {
      data: 'invalid',
      iv: 'invalid',
      algorithm: 'aes-256-gcm'
    };
    
    const decryptResult = await crypto.decrypt(invalidEncrypted, 'some-key');
    expect(decryptResult.isFailure).toBe(true);
  });

  it('should handle invalid private keys in signing', async () => {
    const signResult = await crypto.sign('data', 'invalid-private-key');
    expect(signResult.isFailure).toBe(true);
  });
});

describe('Crypto Unit - Pure Functions', () => {
  // Doctrine #8: PURE FUNCTION HEARTS (functional interface)
  
  it('should provide functional encrypt/decrypt', async () => {
    const keyResult = generateKey();
    expect(keyResult.isSuccess).toBe(true);
    
    const key = keyResult.value;
    const data = 'functional test';
    
    const encryptResult = await encrypt(data, key);
    expect(encryptResult.isSuccess).toBe(true);
    
    const decryptResult = await decrypt(encryptResult.value, key);
    expect(decryptResult.isSuccess).toBe(true);
    expect(decryptResult.value).toBe(data);
  });

  it('should provide functional hashing', () => {
    const hashResult = hash('test data');
    expect(hashResult.isSuccess).toBe(true);
    expect(hashResult.value.hash).toMatch(/^[a-f0-9]+$/);
  });

  it('should provide functional key generation', () => {
    const keyResult = generateKey();
    expect(keyResult.isSuccess).toBe(true);
    expect(keyResult.value).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should provide functional key pair generation', () => {
    const keyPairResult = generateKeyPair('rsa', 2048);
    expect(keyPairResult.isSuccess).toBe(true);
    expect(keyPairResult.value.algorithm).toBe('rsa');
  });

  it('should provide functional signing/verification', async () => {
    const keyPairResult = generateKeyPair('rsa', 2048);
    expect(keyPairResult.isSuccess).toBe(true);
    
    const keyPair = keyPairResult.value;
    const data = 'functional sign test';
    
    const signResult = await sign(data, keyPair.privateKey);
    expect(signResult.isSuccess).toBe(true);
    
    const verifyResult = await verify(data, signResult.value, keyPair.publicKey);
    expect(verifyResult.isSuccess).toBe(true);
    expect(verifyResult.value).toBe(true);
  });
});

describe('Result Pattern Tests', () => {
  // Test the foundational Result pattern
  
  it('should create successful results', () => {
    const result = Result.success('test value');
    
    expect(result.isSuccess).toBe(true);
    expect(result.isFailure).toBe(false);
    expect(result.value).toBe('test value');
  });

  it('should create failed results', () => {
    const error = new Error('test error');
    const result = Result.fail('Operation failed', error);
    
    expect(result.isSuccess).toBe(false);
    expect(result.isFailure).toBe(true);
    expect(result.errorMessage).toBe('Operation failed');
    expect(result.errorCause).toBe(error);
  });

  it('should support result transformation', () => {
    const result = Result.success(5);
    const transformed = result.map(x => x * 2);
    
    expect(transformed.isSuccess).toBe(true);
    expect(transformed.value).toBe(10);
  });

  it('should support result chaining', () => {
    const result = Result.success(5);
    const chained = result.flatMap(x => Result.success(x.toString()));
    
    expect(chained.isSuccess).toBe(true);
    expect(chained.value).toBe('5');
  });

  it('should handle errors in transformation', () => {
    const result = Result.success(5);
    const transformed = result.map(() => {
      throw new Error('Transform error');
    });
    
    expect(transformed.isFailure).toBe(true);
    expect(transformed.errorMessage).toContain('Transform failed');
  });
});
