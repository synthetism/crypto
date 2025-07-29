#!/usr/bin/env node

/**
 * Crypto Unit Demonstration
 * 
 * Shows the foundational crypto unit in action following Unit Architecture doctrine.
 * This demonstrates how the crypto unit can be used both as a conscious unit
 * and through pure functions for serverless deployment.
 */

import { Crypto, encrypt, decrypt, hash, generateKey, generateKeyPair, sign, verify } from '../src/index.js';

console.log('🔐 CRYPTO UNIT DEMONSTRATION - Foundational Cryptographic Operations\n');

// Doctrine #4: CREATE NOT CONSTRUCT
console.log('=== 1. UNIT CREATION & CONSCIOUSNESS ===');
const crypto = Crypto.create({
  algorithm: 'aes-256-gcm',
  keySize: 2048,
  hashAlgorithm: 'sha256'
});

console.log(`Identity: ${crypto.whoami()}`);
console.log(`Capabilities: ${crypto.capabilities().slice(0, 5).join(', ')}...\n`);

// Doctrine #11: ALWAYS HELP  
console.log('=== 2. LIVING DOCUMENTATION ===');
crypto.help();

// Doctrine #8: PURE FUNCTION HEARTS + Symmetric Encryption
console.log('\n=== 3. SYMMETRIC ENCRYPTION DEMO ===');
const keyResult = crypto.generateKey();
if (keyResult.isSuccess) {
  const key = keyResult.value;
  console.log(`Generated Key: ${key.substring(0, 16)}...`);
  
  const data = 'Sensitive data that needs encryption';
  console.log(`Original Data: "${data}"`);
  
  const encryptResult = await crypto.encrypt(data, key);
  if (encryptResult.isSuccess) {
    const encrypted = encryptResult.value;
    console.log(`Encrypted Data: ${encrypted.data.substring(0, 32)}...`);
    console.log(`IV: ${encrypted.iv}`);
    console.log(`Algorithm: ${encrypted.algorithm}`);
    console.log(`Auth Tag: ${encrypted.tag?.substring(0, 16)}...`);
    
    const decryptResult = await crypto.decrypt(encrypted, key);
    if (decryptResult.isSuccess) {
      console.log(`Decrypted Data: "${decryptResult.value}"`);
      console.log(`✅ Encryption/Decryption successful!`);
    }
  }
}

// Hash Demonstration
console.log('\n=== 4. CRYPTOGRAPHIC HASHING ===');
const testData = 'Data to hash for integrity verification';
const hashResult = crypto.hash(testData);
if (hashResult.isSuccess) {
  const hashInfo = hashResult.value;
  console.log(`Input: "${hashInfo.input}"`);
  console.log(`Hash: ${hashInfo.hash}`);
  console.log(`Algorithm: ${hashInfo.algorithm}`);
  console.log(`Timestamp: ${hashInfo.timestamp.toISOString()}`);
}

// Digital Signatures
console.log('\n=== 5. DIGITAL SIGNATURES ===');
const keyPairResult = crypto.generateKeyPair('rsa', 2048);
if (keyPairResult.isSuccess) {
  const keyPair = keyPairResult.value;
  console.log(`Generated ${keyPair.algorithm.toUpperCase()} key pair (${keyPair.keySize} bits)`);
  console.log(`Public Key: ${keyPair.publicKey.substring(0, 50)}...`);
  
  const document = 'Important document that needs digital signature';
  console.log(`Document: "${document}"`);
  
  const signResult = await crypto.sign(document, keyPair.privateKey);
  if (signResult.isSuccess) {
    const signature = signResult.value;
    console.log(`Signature: ${signature.substring(0, 32)}...`);
    
    const verifyResult = await crypto.verify(document, signature, keyPair.publicKey);
    if (verifyResult.isSuccess) {
      console.log(`Signature Valid: ${verifyResult.value ? '✅ YES' : '❌ NO'}`);
    }
    
    // Test with tampered document
    const tamperedDoc = document + ' TAMPERED';
    const verifyTamperedResult = await crypto.verify(tamperedDoc, signature, keyPair.publicKey);
    if (verifyTamperedResult.isSuccess) {
      console.log(`Tampered Document Valid: ${verifyTamperedResult.value ? '✅ YES' : '❌ NO'}`);
    }
  }
}

// Doctrine #9: ALWAYS TEACH - Teaching Capabilities
console.log('\n=== 6. TEACHING CONTRACT DEMONSTRATION ===');
const teaching = crypto.teach();
console.log(`Unit ID: ${teaching.unitId}`);
console.log(`Teachable Capabilities: ${Object.keys(teaching.capabilities).join(', ')}`);

// Simulate learning (in a real scenario, another unit would learn these capabilities)
console.log('\nSimulating capability execution through teaching contract:');
const capabilityKeys = Object.keys(teaching.capabilities);
for (const cap of capabilityKeys.slice(0, 3)) {
  console.log(`- ${teaching.unitId}.${cap}`);
}

// Doctrine #8: PURE FUNCTION HEARTS - Functional Interface
console.log('\n=== 7. PURE FUNCTIONAL INTERFACE ===');
console.log('Demonstrating serverless-friendly pure functions:');

const functionalKeyResult = generateKey();
if (functionalKeyResult.isSuccess) {
  const functionalKey = functionalKeyResult.value;
  console.log(`Functional Key: ${functionalKey.substring(0, 16)}...`);
  
  const functionalData = 'Serverless function data';
  const functionalEncryptResult = await encrypt(functionalData, functionalKey);
  if (functionalEncryptResult.isSuccess) {
    console.log(`Functional Encrypt: ${functionalEncryptResult.value.data.substring(0, 32)}...`);
    
    const functionalDecryptResult = await decrypt(functionalEncryptResult.value, functionalKey);
    if (functionalDecryptResult.isSuccess) {
      console.log(`Functional Decrypt: "${functionalDecryptResult.value}"`);
    }
  }
}

// Random Bytes for Secure Operations
console.log('\n=== 8. SECURE RANDOM GENERATION ===');
const randomResult = crypto.randomBytes(32);
if (randomResult.isSuccess) {
  console.log(`Random Bytes (32): ${randomResult.value}`);
}

// Domain Export
console.log('\n=== 9. DOMAIN REPRESENTATION ===');
const domain = crypto.toDomain();
console.log('Crypto Capabilities for External Systems:');
Object.entries(domain).forEach(([capability, algorithm]) => {
  console.log(`  ${capability}: ${algorithm}`);
});

// Final Status
console.log('\n=== 10. UNIT STATUS ===');
console.log(`Operations completed successfully`);
console.log(`Unit remains immutable and conscious`);
console.log(`Ready for deployment to serverless environments`);
console.log(`Zero external dependencies - maximum freedom! 🚀`);

console.log('\n🔐 Crypto Unit demonstration completed successfully!');
console.log('This unit is ready for:');
console.log('• Serverless deployment (Cloudflare Workers, Lambda, etc.)');
console.log('• Teaching other units crypto capabilities');
console.log('• Pure functional usage in stateless environments');
console.log('• Integration with @synet/registry for remote capability sharing');
