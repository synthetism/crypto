# @synet/crypto Manual

Advanced usage guide for foundational cryptographic operations in the SYNET ecosystem.

## Table of Contents

- [Configuration](#configuration)
- [Symmetric Encryption](#symmetric-encryption)
- [Digital Signatures](#digital-signatures) 
- [Key Derivation](#key-derivation)
- [Unit Architecture Integration](#unit-architecture-integration)
- [Serverless Deployment](#serverless-deployment)
- [Error Handling](#error-handling)
- [Use Cases & Scenarios](#use-cases--scenarios)
- [Performance Considerations](#performance-considerations)

## Configuration

### Basic Configuration

```typescript
import { Crypto } from '@synet/crypto';

// Default configuration
const crypto = Crypto.create();

// Custom configuration  
const customCrypto = Crypto.create({
  algorithm: 'aes-128-gcm',     // or 'aes-256-gcm' (default)
  keySize: 4096,               // RSA key size: 256|512|1024|2048|4096
  hashAlgorithm: 'sha512',     // or 'sha256' (default), 'sha3-512'
  metadata: { environment: 'production' }
});
```

### Unit Inspection

```typescript
// Check unit capabilities and configuration
console.log(crypto.capabilities());
console.log(crypto.whoami());
crypto.help(); // Comprehensive help documentation
```

## Symmetric Encryption

### AES-GCM Encryption

```typescript
const crypto = Crypto.create();
const sensitiveData = 'Customer PII data';
const encryptionKey = crypto.generateKey(32); // 256-bit key

const encrypted = crypto.encrypt(sensitiveData, encryptionKey);
if (encrypted.isSuccess) {
  const { data, iv, tag, algorithm } = encrypted.value;
  
  // Store all components - they're all needed for decryption
  const storedData = { data, iv, tag, algorithm };
  
  // Later decryption
  const decrypted = crypto.decrypt(storedData, encryptionKey);
  if (decrypted.isSuccess) {
    console.log('Original data:', decrypted.value);
  }
}
```

### Key Management

```typescript
// Generate different key sizes
const key128 = crypto.generateKey(16);  // 128-bit
const key256 = crypto.generateKey(32);  // 256-bit  
const key512 = crypto.generateKey(64);  // 512-bit

// Secure random bytes for salts, nonces
const salt = crypto.randomBytes(16);
const nonce = crypto.randomBytes(32);
```

## Digital Signatures

### RSA Signatures

```typescript
const crypto = Crypto.create();

// Generate RSA key pair
const keyPair = crypto.generateKeyPair('rsa', 2048);

const document = 'Important contract terms';

// Sign document
const signature = crypto.sign(document, keyPair.privateKey);
if (signature.isSuccess) {
  // Verify signature
  const verification = crypto.verify(document, signature.value, keyPair.publicKey);
  if (verification.isSuccess && verification.value) {
    console.log('✅ Signature valid');
  } else {
    console.log('❌ Signature invalid');
  }
}
```

### Elliptic Curve Signatures

```typescript
// EC signatures (prime256v1 curve)
const ecKeyPair = crypto.generateKeyPair('ec');
const signature = crypto.sign(document, ecKeyPair.privateKey);
```

### Tamper Detection

```typescript
const originalDoc = 'Original terms';
const tamperedDoc = 'Modified terms';

const signature = crypto.sign(originalDoc, keyPair.privateKey);
if (signature.isSuccess) {
  // This will return false - detects tampering
  const verification = crypto.verify(tamperedDoc, signature.value, keyPair.publicKey);
  console.log('Tampered doc verified:', verification.value); // false
}
```

## Key Derivation

### PBKDF2 - Password-Based Keys

```typescript
const crypto = Crypto.create();

// User authentication scenario
const userPassword = 'user_secure_password';
const salt = crypto.randomBytes(16);
const iterations = 100000; // Higher = more secure but slower

const derivedKey = crypto.deriveKeyPBKDF2(userPassword, salt, iterations, 32);

console.log('Derived key:', derivedKey.derivedKey);
console.log('Salt:', derivedKey.salt);
console.log('Algorithm:', derivedKey.algorithm); // 'pbkdf2'
console.log('Iterations:', derivedKey.iterations);
```

### HKDF - Protocol Key Derivation

```typescript
// Protocol key derivation (RFC 5869)
const sharedSecret = crypto.randomBytes(32);
const salt = crypto.randomBytes(16);
const protocolInfo = 'TLS 1.3 handshake';

const protocolKey = crypto.deriveKeyHKDF(sharedSecret, salt, protocolInfo, 32);

console.log('Protocol key:', protocolKey.derivedKey);
console.log('Algorithm:', protocolKey.algorithm); // 'hkdf-sha256'
```

### Scrypt - Memory-Hard Derivation

```typescript
// Memory-hard key derivation (anti-ASIC)
const password = 'user_password';
const salt = crypto.randomBytes(16);

// Customize memory/CPU parameters
const options = {
  N: 16384,  // Memory cost parameter
  r: 8,      // Block size parameter  
  p: 1       // Parallelization parameter
};

const scryptKey = crypto.deriveKeyScrypt(password, salt, 32, options);
console.log('Scrypt key:', scryptKey.derivedKey);
console.log('Algorithm:', scryptKey.algorithm); // 'scrypt-N16384-r8-p1'
```

## Unit Architecture Integration

### Teaching Capabilities

```typescript
const crypto = Crypto.create();

// Get teaching contract
const contract = crypto.teach();
console.log('Unit ID:', contract.unitId); // 'crypto'
console.log('Capabilities:', Object.keys(contract.capabilities));

// Capabilities include all native operations:
// encrypt, decrypt, hash, sign, verify, generateKey, etc.
```

### Learning from Other Units

```typescript
// Create units that can learn from each other
const crypto = Crypto.create();
const storage = StorageUnit.create();

// Storage unit learns crypto capabilities
storage.learn([crypto.teach()]);

// Now storage can encrypt data before storing
if (storage.can('crypto.encrypt')) {
  const encrypted = storage.execute('crypto.encrypt', sensitiveData, key);
}
```

### Capability Composition

```typescript
// Multiple units can share and compose capabilities
const crypto = Crypto.create();
const hasher = HasherUnit.create();
const logger = LoggerUnit.create();

// Create a composite unit with multiple capabilities
const secureLogger = LoggerUnit.create();
secureLogger.learn([
  crypto.teach(),
  hasher.teach()
]);

// Now secureLogger can encrypt and hash logs
const logData = 'User action logged';
const hashedLog = secureLogger.execute('hasher.hash', logData);
const encryptedLog = secureLogger.execute('crypto.encrypt', logData, key);
```

## Serverless Deployment

### Cloudflare Workers

```typescript
// worker.ts
import { encrypt, decrypt, hash } from '@synet/crypto/functions';

export default {
  async fetch(request: Request): Promise<Response> {
    const data = await request.text();
    
    // Stateless operations - perfect for Workers
    const key = generateKey(32);
    const encrypted = encrypt(data, key);
    const signature = hash(data + key);
    
    return new Response(JSON.stringify({ encrypted, signature }));
  }
};
```

### AWS Lambda

```typescript
// lambda.ts
import { deriveKeyPBKDF2, encrypt } from '@synet/crypto/functions';

export const handler = async (event: any) => {
  const { password, data } = event;
  
  // Derive key from password
  const salt = generateKey(16);
  const derivedKey = deriveKeyPBKDF2(password, salt, 100000);
  
  // Encrypt data
  const encrypted = encrypt(data, derivedKey.derivedKey);
  
  return {
    statusCode: 200,
    body: JSON.stringify({ encrypted, salt })
  };
};
```

## Error Handling

### Simple Operations (Throw)

```typescript
try {
  const key = crypto.generateKey(32);
  const hash = crypto.hash('data');
  const keyPair = crypto.generateKeyPair('rsa', 2048);
  const bytes = crypto.randomBytes(16);
  const derived = crypto.deriveKeyPBKDF2('password', salt);
} catch (error) {
  console.error('Crypto operation failed:', error.message);
}
```

### Complex Operations (Result Pattern)

```typescript
const encrypted = crypto.encrypt(data, key);
if (encrypted.isFailure) {
  console.error('Encryption failed:', encrypted.error);
  console.error('Original error:', encrypted.errorCause);
  return;
}

const decrypted = crypto.decrypt(encrypted.value, wrongKey);
if (decrypted.isFailure) {
  console.error('Decryption failed:', decrypted.error);
  // Handle gracefully - don't crash the application
}
```

### Error Cause Tracking

```typescript
const result = crypto.encrypt(invalidData, malformedKey);
if (result.isFailure) {
  console.log('Error message:', result.error);
  console.log('Original cause:', result.errorCause); // Original Error object
  
  // Detailed debugging information available
  if (result.errorCause instanceof Error) {
    console.log('Stack trace:', result.errorCause.stack);
  }
}
```

## Use Cases & Scenarios

### 1. User Authentication System

```typescript
// Registration - store password hash
const registerUser = (password: string) => {
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.deriveKeyPBKDF2(password, salt, 100000);
  
  // Store salt and derivedKey.derivedKey in database
  return { userId: generateUserId(), salt, hash: derivedKey.derivedKey };
};

// Login - verify password
const authenticateUser = (password: string, storedSalt: string, storedHash: string) => {
  const derivedKey = crypto.deriveKeyPBKDF2(password, storedSalt, 100000);
  return derivedKey.derivedKey === storedHash;
};
```

### 2. API Request Signing

```typescript
// Generate API key pair for client
const apiKeyPair = crypto.generateKeyPair('rsa', 2048);

// Client signs requests
const signRequest = (requestBody: string, privateKey: string) => {
  const timestamp = Date.now().toString();
  const payload = requestBody + timestamp;
  
  const signature = crypto.sign(payload, privateKey);
  return { signature: signature.isSuccess ? signature.value : null, timestamp };
};

// Server verifies requests
const verifyRequest = (requestBody: string, signature: string, timestamp: string, publicKey: string) => {
  const payload = requestBody + timestamp;
  const verification = crypto.verify(payload, signature, publicKey);
  return verification.isSuccess && verification.value;
};
```

### 3. Secure File Storage

```typescript
// Encrypt files before storage
const secureFileStorage = {
  store: (filename: string, content: string, userPassword: string) => {
    // Derive encryption key from user password
    const salt = crypto.randomBytes(16);
    const derivedKey = crypto.deriveKeyPBKDF2(userPassword, salt, 100000);
    
    // Encrypt file content
    const encrypted = crypto.encrypt(content, derivedKey.derivedKey);
    
    if (encrypted.isSuccess) {
      // Store encrypted data + salt
      return { 
        filename, 
        encrypted: encrypted.value, 
        salt,
        success: true 
      };
    }
    return { success: false, error: encrypted.error };
  },
  
  retrieve: (encryptedData: any, userPassword: string) => {
    // Derive same key from password + stored salt
    const derivedKey = crypto.deriveKeyPBKDF2(userPassword, encryptedData.salt, 100000);
    
    // Decrypt file content
    const decrypted = crypto.decrypt(encryptedData.encrypted, derivedKey.derivedKey);
    
    return decrypted.isSuccess ? decrypted.value : null;
  }
};
```

### 4. Blockchain/DID Integration

```typescript
// For identity/DID scenarios, prefer @synet/keys for Ed25519/secp256k1
// But @synet/crypto provides foundational operations

const createSecureIdentity = () => {
  // Generate identity key pair
  const keyPair = crypto.generateKeyPair('ec'); // Or use @synet/keys for Ed25519
  
  // Create identity hash
  const identityData = {
    publicKey: keyPair.publicKey,
    created: new Date().toISOString(),
    version: '1.0.0'
  };
  
  const identityHash = crypto.hash(JSON.stringify(identityData));
  
  // Sign identity for verification
  const signature = crypto.sign(identityHash.hash, keyPair.privateKey);
  
  return {
    identity: identityData,
    hash: identityHash.hash,
    signature: signature.isSuccess ? signature.value : null,
    privateKey: keyPair.privateKey // Keep secure!
  };
};
```

### 5. Protocol Key Exchange

```typescript
// Implement key derivation for secure protocols
const protocolKeyExchange = {
  // Phase 1: Generate ephemeral key pair
  generateEphemeralKeys: () => crypto.generateKeyPair('ec'),
  
  // Phase 2: Derive shared secret (simplified - use proper ECDH in production)
  deriveSharedSecret: (sharedInput: string) => {
    const salt = crypto.randomBytes(16);
    return crypto.deriveKeyHKDF(sharedInput, salt, 'protocol-v1', 32);
  },
  
  // Phase 3: Derive session keys
  deriveSessionKeys: (sharedSecret: string) => {
    const salt = crypto.randomBytes(16);
    
    const encryptionKey = crypto.deriveKeyHKDF(sharedSecret, salt, 'encryption', 32);
    const macKey = crypto.deriveKeyHKDF(sharedSecret, salt, 'authentication', 32);
    
    return { encryptionKey, macKey };
  }
};
```

## Performance Considerations

### Key Derivation Performance

```typescript
// PBKDF2 iterations vs security vs performance
const performanceTest = {
  // Fast but less secure (development only)
  development: () => crypto.deriveKeyPBKDF2(password, salt, 1000),
  
  // Balanced for production
  production: () => crypto.deriveKeyPBKDF2(password, salt, 100000),
  
  // High security (servers with good CPU)
  highSecurity: () => crypto.deriveKeyPBKDF2(password, salt, 500000),
  
  // Memory-hard alternative
  memoryHard: () => crypto.deriveKeyScrypt(password, salt, 32, { N: 16384, r: 8, p: 1 })
};
```

### Serverless Optimization

```typescript
// Pre-generate keys when possible
const optimizedServerless = {
  // Cache generated keys in environment variables
  getStaticKey: () => process.env.STATIC_ENCRYPTION_KEY || generateKey(32),
  
  // Use minimal iterations for serverless constraints
  fastDerivation: (password: string, salt: string) => 
    deriveKeyPBKDF2(password, salt, 10000), // Lower for cold starts
  
  // Batch operations when possible
  batchEncrypt: (dataArray: string[], key: string) => 
    dataArray.map(data => encrypt(data, key))
};
```

### Memory Management

```typescript
// Unit creation is lightweight - create as needed
const createOnDemand = () => {
  // Each crypto unit is stateless - no memory leaks
  const crypto = Crypto.create();
  const result = crypto.encrypt(data, key);
  // Unit can be garbage collected immediately
  return result;
};

// For high-frequency operations, reuse units
const highFrequency = (() => {
  const crypto = Crypto.create();
  return {
    encrypt: (data: string, key: string) => crypto.encrypt(data, key),
    decrypt: (encrypted: any, key: string) => crypto.decrypt(encrypted, key)
  };
})();
```

---

## Next Steps

- **@synet/keys** - For identity operations (Ed25519, secp256k1, X25519, WireGuard)
- **@synet/vault** - For secure key storage and management
- **@synet/identity** - For DID operations and identity management
- **@synet/patterns** - For additional Result pattern utilities

## Support

See Unit Architecture documentation for comprehensive patterns and examples.
